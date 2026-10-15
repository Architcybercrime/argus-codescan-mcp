import { execa } from "execa";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { listReviewFiles, runReview } from "../src/review.js";
import { runReviewCli } from "../src/review-cli.js";
import { runAllSast } from "../src/scanners/sast.js";
import { runAllSecrets } from "../src/scanners/secrets.js";
import { runNativeSast } from "../src/scanners/native-sast.js";

vi.mock("../src/scanners/sast.js", () => ({ runAllSast: vi.fn() }));
vi.mock("../src/scanners/secrets.js", () => ({ runAllSecrets: vi.fn() }));
vi.mock("../src/scanners/tools.js", () => ({ isToolAvailable: async () => false }));

let root: string;
async function git(...args: string[]): Promise<string> {
  const { stdout } = await execa("git", args, { cwd: root });
  return stdout;
}
async function put(name: string, content = "safe\n"): Promise<void> {
  await mkdir(dirname(join(root, name)), { recursive: true });
  await writeFile(join(root, name), content);
}
async function commit(): Promise<void> {
  await git("add", ".");
  await git("commit", "-qm", "fixture");
}

beforeEach(async () => {
  vi.resetAllMocks();
  root = await mkdtemp(join(tmpdir(), "argus-review-test-"));
  await git("init", "-q");
  await git("config", "user.name", "Review Test");
  await git("config", "user.email", "review@example.invalid");
  await git("config", "core.autocrlf", "false");
  await put("tracked.js");
  await put("deleted.js");
  await put("unchanged.js");
  await put(".gitignore", "ignored.js\n");
  await commit();
  vi.mocked(runAllSast).mockResolvedValue([]);
  vi.mocked(runAllSecrets).mockResolvedValue([]);
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

describe("changed-file selection", () => {
  it("includes dirty and untracked files, preserves unusual names and skips deleted/ignored files", async () => {
    await put("tracked.js", "changed\n");
    await rm(join(root, "deleted.js"));
    for (const name of ["space name.ts", "日本語.ts", "ignored.js", "node_modules/pkg/a.js"]) {
      await put(name);
    }
    if (process.platform !== "win32") await put("line\nbreak.ts");
    const result = await listReviewFiles(join(root, "tracked.js"));
    const expected = ["space name.ts", "tracked.js", "日本語.ts"];
    if (process.platform !== "win32") expected.unshift("line\nbreak.ts");
    expect(result.files).toEqual(expected);
  });

  it("combines branch changes, dirty files and untracked files with --base", async () => {
    const base = await git("rev-parse", "HEAD");
    await put("branch.ts");
    await commit();
    await put("tracked.js", "dirty\n");
    await put("untracked.ts");
    expect((await listReviewFiles(root, { base })).files).toEqual([
      "branch.ts", "tracked.js", "untracked.ts",
    ]);
  });

  it("rejects an invalid base and conflicting selection modes", async () => {
    await expect(listReviewFiles(root, { base: "--help" })).rejects.toThrow();
    await expect(listReviewFiles(root, { base: "HEAD", staged: true })).rejects.toThrow("either");
  });

  it("includes renamed destinations and excludes staged deletions", async () => {
    await git("mv", "tracked.js", "renamed.js");
    await git("rm", "deleted.js");
    expect((await listReviewFiles(root, { staged: true })).files).toEqual(["renamed.js"]);
  });

  it("handles an initial repository without HEAD", async () => {
    const fresh = join(root, "fresh");
    await mkdir(fresh);
    await execa("git", ["init", "-q"], { cwd: fresh });
    await writeFile(join(fresh, "new.ts"), "safe\n");
    expect((await listReviewFiles(fresh)).files).toEqual(["new.ts"]);
  });
});

describe("review snapshots", () => {
  it("runs the existing secret pattern scanner against the changed-file snapshot", async () => {
    const secrets = await vi.importActual<typeof import("../src/scanners/secrets.js")>(
      "../src/scanners/secrets.js",
    );
    vi.mocked(runAllSecrets).mockImplementation(secrets.runAllSecrets);
    await put("new.ts", `const api_key = '${"x".repeat(20)}';\n`);
    const { report } = await runReview(root);
    expect(report.results.flatMap((result) => result.findings)).toEqual([
      expect.objectContaining({ file: "new.ts", ruleId: "Generic API Key", severity: "high" }),
    ]);
  });

  it("scans only changed working files and remaps absolute finding paths", async () => {
    await put("tracked.js", "eval(input);\n");
    let tree = "";
    vi.mocked(runAllSast).mockImplementation(async (target) => {
      tree = target;
      expect(existsSync(join(target, "unchanged.js"))).toBe(false);
      const result = await runNativeSast(target);
      for (const finding of result.findings) finding.file = join(target, finding.file!);
      return [result];
    });
    const { report, files } = await runReview(root);
    expect(files).toEqual(["tracked.js"]);
    expect(report.summary.high).toBeGreaterThan(0);
    expect(report.results[0].target).toBe(report.target);
    expect(report.results[0].findings[0].file).toBe("tracked.js");
    expect(existsSync(tree)).toBe(false);
    expect(await readFile(join(root, "tracked.js"), "utf8")).toBe("eval(input);\n");
  });

  it("scans index contents despite later edits or working-tree deletion", async () => {
    await put("tracked.js", "staged content\n");
    await put("space 日本語.ts", "staged addition\n");
    await git("add", ".");
    await put("tracked.js", "unstaged content\n");
    await rm(join(root, "space 日本語.ts"));
    await put("untracked.js");
    vi.mocked(runAllSecrets).mockImplementation(async (tree) => {
      expect(await readFile(join(tree, "tracked.js"), "utf8")).toBe("staged content\n");
      expect(await readFile(join(tree, "space 日本語.ts"), "utf8")).toBe("staged addition\n");
      expect(existsSync(join(tree, "untracked.js"))).toBe(false);
      return [];
    });
    expect((await runReview(root, { staged: true })).files).toEqual(["space 日本語.ts", "tracked.js"]);
    expect(await git("show", ":tracked.js")).toBe("staged content");
  });

  it.skipIf(process.platform === "win32")("skips symlinks in working-tree and index snapshots", async () => {
    await symlink(join(root, "tracked.js"), join(root, "link.js"));
    expect((await runReview(root)).files).toEqual([]);
    await git("add", "link.js");
    expect((await runReview(root, { staged: true })).files).toEqual([]);
    expect(runAllSast).not.toHaveBeenCalled();
  });

  it("returns an empty report without invoking scanners for an empty diff", async () => {
    const { report, files } = await runReview(root);
    expect(files).toEqual([]);
    expect(report.summary.total).toBe(0);
    expect(runAllSast).not.toHaveBeenCalled();
    expect(runAllSecrets).not.toHaveBeenCalled();
  });

  it("does not scan unstaged-only changes when --staged is selected", async () => {
    await put("tracked.js", "unstaged\n");
    await put("untracked.js");
    expect((await runReview(root, { staged: true })).files).toEqual([]);
    expect(runAllSast).not.toHaveBeenCalled();
  });

  it("waits for other scanners and cleans the tree when a scanner rejects", async () => {
    await put("new.js");
    let tree = "";
    vi.mocked(runAllSast).mockRejectedValue(new Error("scanner failed"));
    vi.mocked(runAllSecrets).mockImplementation(async (target) => {
      tree = target;
      await new Promise((done) => setTimeout(done, 20));
      expect(existsSync(join(target, "new.js"))).toBe(true);
      return [];
    });
    await expect(runReview(root)).rejects.toThrow("scanner failed");
    expect(existsSync(tree)).toBe(false);
  });
});

describe("review CLI", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("prints clean JSON for an empty diff without writing CSV when requested", async () => {
    expect(await runReviewCli([root, "--format", "json", "--no-csv"])).toBe(0);
    expect(JSON.parse(vi.mocked(console.log).mock.calls[0][0]).scanType).toBe("review");
    expect(console.error).toHaveBeenCalledWith("No changed files to review.");
  });

  it.each([["--base"], ["--format", "xml"], ["--fail-on", "invalid"], ["--unknown"], [".", "."]])(
    "rejects invalid arguments: %j", async (...args) => {
      expect(await runReviewCli(args)).toBe(1);
      expect(runAllSast).not.toHaveBeenCalled();
    },
  );

  it("writes the requested CSV and returns the existing findings exit status", async () => {
    await put("new.js", "eval(input);\n");
    vi.mocked(runAllSast).mockImplementation(async (tree) => [await runNativeSast(tree)]);
    const output = join(root, "report.csv");
    expect(await runReviewCli([root, "--output", output, "--fail-on", "high"])).toBe(1);
    expect(await readFile(output, "utf8")).toContain("new.js");
  });

  it("shows review-specific help", async () => {
    expect(await runReviewCli(["--help"])).toBe(0);
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("--staged"));
  });

  it("reports a non-repository target as a review error", async () => {
    expect(await runReviewCli([tmpdir(), "--no-csv"])).toBe(1);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("Review failed:"));
  });
});
