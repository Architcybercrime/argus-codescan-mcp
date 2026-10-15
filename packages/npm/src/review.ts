/** Native SAST and secrets review of a temporary snapshot of changed files. */
import { execa } from "execa";
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { buildReport } from "./scanners/report.js";
import { runAllSast } from "./scanners/sast.js";
import { runAllSecrets } from "./scanners/secrets.js";
import type { ScanReport } from "./scanners/types.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "vendor",
  "__pycache__", "target", "bin", "obj", ".venv", "venv",
]);

export interface ReviewOptions {
  staged?: boolean;
  base?: string;
}

async function git(root: string, args: string[]): Promise<string> {
  const { stdout } = await execa("git", ["--literal-pathspecs", ...args], {
    cwd: root, stripFinalNewline: false,
  });
  return stdout;
}

/** Locate the repository and list changed paths without Git's filename quoting. */
export async function listReviewFiles(target: string, options: ReviewOptions = {}): Promise<{
  repoRoot: string;
  files: string[];
}> {
  if (options.staged && options.base) throw new Error("Use either --staged or --base, not both.");
  const path = resolve(target);
  const cwd = (await lstat(path)).isDirectory() ? path : dirname(path);
  const repoRoot = (await git(cwd, ["rev-parse", "--show-toplevel"])).replace(/\r?\n$/, "");
  const names: string[] = [];
  const add = async (args: string[]) => {
    names.push(...(await git(repoRoot, args)).split("\0").filter(Boolean));
  };
  const diff = ["diff", "--name-only", "-z", "--diff-filter=ACMR"];
  if (options.staged) {
    await add([...diff, "--cached", "--"]);
  } else {
    if (options.base) {
      // Resolve a revision first so user input cannot be interpreted as a Git option.
      const base = (await git(repoRoot, [
        "rev-parse", "--verify", "--end-of-options", `${options.base}^{commit}`,
      ])).trim();
      await add([...diff, `${base}...HEAD`, "--"]);
    }
    const head = await execa("git", ["rev-parse", "--verify", "HEAD"], {
      cwd: repoRoot, reject: false,
    });
    if (head.exitCode === 0) {
      await add([...diff, "HEAD", "--"]);
    } else {
      await add([...diff, "--cached", "--"]);
      await add([...diff, "--"]);
    }
    await add(["ls-files", "--others", "--exclude-standard", "-z", "--"]);
  }
  const files = [...new Set(names)].filter((name) => {
    const rel = relative(repoRoot, resolve(repoRoot, name));
    return rel !== "" && !isAbsolute(rel) && rel !== ".." &&
      !rel.startsWith(`..${sep}`) && !name.split("/").some((part) => SKIP_DIRS.has(part));
  }).sort();
  return { repoRoot, files };
}

/** Scan index contents in staged mode and working-tree contents otherwise. */
export async function runReview(target: string, options: ReviewOptions = {}): Promise<{
  report: ScanReport;
  files: string[];
}> {
  const { repoRoot, files } = await listReviewFiles(target, options);
  if (files.length === 0) return { report: buildReport(repoRoot, "review", []), files: [] };
  const tree = await mkdtemp(join(tmpdir(), "argus-review-"));
  const copied: string[] = [];
  try {
    for (const name of files) {
      let content: Uint8Array;
      if (options.staged) {
        const entry = await git(repoRoot, ["ls-files", "--stage", "-z", "--", name]);
        // Never materialise symlinks or submodules as source files.
        if (!entry.startsWith("100644 ") && !entry.startsWith("100755 ")) continue;
        const result = await execa("git", ["show", `:${name}`], {
          cwd: repoRoot, encoding: "buffer", stripFinalNewline: false,
        });
        content = result.stdout;
      } else {
        const source = join(repoRoot, name);
        try {
          // Check every component to avoid following directory symlinks outside the repo.
          let current = repoRoot;
          let symlink = false;
          for (const part of name.split("/")) {
            current = join(current, part);
            if ((await lstat(current)).isSymbolicLink()) { symlink = true; break; }
          }
          if (symlink || !(await lstat(source)).isFile()) continue;
          content = await readFile(source);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
          throw err;
        }
      }
      const destination = join(tree, name);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, content, { mode: 0o600 });
      copied.push(name);
    }
    if (copied.length === 0) return { report: buildReport(repoRoot, "review", []), files: [] };
    // Wait for both batches before cleanup, even when one scanner rejects.
    const batches = await Promise.allSettled([runAllSast(tree), runAllSecrets(tree)]);
    const results = batches.flatMap((batch) => {
      if (batch.status === "rejected") throw batch.reason;
      return batch.value;
    });
    for (const result of results) {
      result.target = repoRoot;
      for (const finding of result.findings) {
        if (!finding.file) continue;
        const path = isAbsolute(finding.file) ? relative(tree, finding.file) : finding.file;
        finding.file = path.split(sep).join("/");
      }
    }
    return { report: buildReport(repoRoot, "review", results), files: copied };
  } finally {
    await rm(tree, { recursive: true, force: true });
  }
}
