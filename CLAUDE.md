# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`lpass` — LastPass command line client. Standalone C99 project (GPLv2+ with OpenSSL exception), flat source layout, no subdirectories for code. Deps: OpenSSL/LibreSSL, libcurl, libxml2, CMake ≥3.1, pkg-config. Docs build needs `asciidoc`/`a2x`.

## Build & test

```bash
make                 # configures cmake in ./build, builds ./build/lpass
make test            # builds ./build/lpass-test + lpass-unit-test, runs ctest
make clean           # removes ./build
make doc-man         # lpass.1.txt -> manpage (asciidoc)
```

Single test (after `make test` or `make -C build lpass-test`):

```bash
test/tests test_show                          # one test function; no arg = all
(cd build && ctest -R '^test_show$' --output-on-failure)
build/lpass-unit-test                         # C unit tests (ctest name: test_unit)
```

- `lpass-test` = all `*.c` + `test/*.c` built with `-DTEST_BUILD`. `test/http_mock.c` overrides `http_post_lastpass_v_noexit` (guarded by `#ifndef TEST_BUILD` in `http.c`). Mock only serves `getaccts`, `iterations`, `login`, `login_check`, `show_website`; any other page returns an "unimplemented" error. Tests must use `--sync=no`, except upload tests: the uploader `chdir("/")`s, so they need an absolute `LPASS_HOME` (subshell) and drain the queue with `lpass sync`.
- Mock env switches: `LPASS_TEST_GCM_WRITE=1` → login/login_check send `enable_aes_gcm_write="1"`; `LPASS_TEST_GCM_TAMPERED=1` → extra account `0006` with a bad GCM tag; `LPASS_TEST_GCM_TAMPERED_FIELDS=1` → secure note `0007` with a bad note tag and account `0008` with a bad group tag. Set them on `login` (later `--sync=no` commands read the cached blob); `--sync=now` tests that don't need a log access use `ls` (`show` enqueues `loglogin.php` and starts the uploader). `show_website` appends the uploaded encrypted params to `$LPASS_HOME/mock-uploads`.
- Tests are bash functions in `test/tests`. New test = add function **and** an `add_test(...)` line in `CMakeLists.txt`, otherwise `make test` skips it.
- `lpass-unit-test` (`EXCLUDE_FROM_ALL`) = all `*.c` except `lpass.c` + `test/unit/*.c`, own `main`, no `TEST_BUILD`/mock. Used for crypto/blob-level tests (`test/unit/cipher_test.c`).
- Mock account `0005` (`test-gcm-account`) holds AES-GCM fields; `ls`/`export` expectations in `test/tests` include it — update both when adding mock accounts.
- Test state lives in `test/.lpass` (`LPASS_HOME`), gitignored.
- Source files are collected with `file(GLOB)` at configure time — re-run cmake (`make clean && make`) after adding/removing `.c` files. `make clean` deletes `./build`, and CMake ≥4 rejects `cmake_minimum_required(3.1)`: reconfigure with `mkdir -p build && cd build && cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX=/usr ..`.
- No linter. Warnings are the check: `-std=gnu99 -pedantic -Wall -Wextra`.
- `contrib/Dockerfile.dev` builds, tests, and installs in a Debian container if the host lacks the toolchain.

## Code layout

- `lpass.c` — `main`, global `commands[]` table (`CMD(name)` → `cmd_<name>` + `cmd_<name>_usage`), alias expansion (`alias.<cmd>` in config), `env` file loading. `umask(0077)` at top of `main` must stay.
- `cmd.h` / `cmd.c` — command prototypes + usage strings; shared helpers (`init_all`, account search by name/id/regex/substr, arg parsers). `cmd-<name>.c` — one file per subcommand, each parses its own `getopt_long` options.
- Adding a command: new `cmd-foo.c`, prototype + `cmd_foo_usage` in `cmd.h` (above the final `#endif` — `cmd_mv`/`cmd_import` currently sit below it), `CMD(foo)` in `lpass.c`, then update `lpass.1.txt` and `contrib/` completions (bash, zsh, fish).

## Core data flow

Every vault command starts with `init_all(sync, key, &session, &blob)`:

1. **Key** — `agent_get_decryption_key` (`agent.c`). Agent is a forked daemon holding the derived AES key, served over a Unix socket in the config dir. Peer must match uid, gid, and same executable (`process_is_same_executable`). Timeout `LPASS_AGENT_TIMEOUT` (default 1h, 0 = never). Fallbacks: `plaintext_key` file (`login --plaintext-key`), or master password prompt verified against the encrypted `verify` file. `kdf.c` derives login hash and decryption key from username/password/iterations (PBKDF2-HMAC-SHA256; CommonCrypto on macOS).
2. **Session** — `session_load(key)`: session id/token/server/private key stored encrypted in the config dir (`session.c`).
3. **Blob** — `blob_load(sync, ...)` (`blob.c`): encrypted local cache of the vault. `auto` re-fetches only if the cache is older than `LPASS_AUTO_SYNC_TIME` (default 5s) and the server version is newer; `now` always fetches; `no` never does. Blob is a chunk stream (`LPAV`, `ACCT`, `ACFL`/`ACOF`, `SHAR`, `ATTA`) parsed by `blob_parse`; server XML responses go through `xml.c`.

**Writes:** `lastpass_update_account` / `lastpass_remove_account` (`endpoints.c`) update the local blob, then `upload_queue_enqueue` (`upload-queue.c`) writes an encrypted entry to `upload-queue/` in the config dir. A forked background process (`upload_queue_ensure_running`) posts entries to the server; failures are kept in `upload-fail/` for 14 days.

**Crypto model:** `struct account` holds each sensitive field in both plaintext and `*_encrypted` form. Always mutate via `account_set_*` / `field_set_value` so the encrypted copy is regenerated; shared-folder items encrypt with `account->share->key`, not the user key. `cipher.c` = AES-256 + RSA for share keys. Formats: `#` + 12B IV + ct + 16B tag (GCM); `!` + 16B IV + CBC; legacy unprefixed ECB (decrypt only, never written).
- **Write mode:** GCM when `feature_flag.aes_gcm_write_enabled`, else CBC. Flag = login/login_check XML attr `enable_aes_gcm_write="1"` (server omits it when off; `xml_login_check` resets it), persisted as `session_ff_aes_gcm_write`. Mode = `cipher_write_mode(&session->feature_flag)`, passed into `account_set_*` / `field_set_value` / `encrypt_and_base64` / `cipher_encrypt_private_key`. Only changed fields are re-encrypted; `account_reencrypt` (share move) and `lpass passwd` re-encrypt everything. `enc_username` (`cmd-passwd.c`) stays CBC regardless.
- Layout detection is structural (`layout_fitting`), not just first byte: raw ECB blob data can start with `#`/`!`. `aes256_decrypt` tries GCM → CBC → ECB.
- Base64 text form is `<marker>b64(iv)|b64(data)`; `cipher_base64` / `cipher_unbase64` handle both `!` and `#`. `blob.c:read_crypt_string` stores `*_encrypted` via `cipher_aes_decrypt_mode` + `cipher_base64_mode` (form of the mode that decrypted), so unchanged fields round-trip untouched; edited fields are re-encrypted per the write mode.
- Decrypt failure → one stderr `Error: AES-GCM authentication failed: account <id>, field <name>` per field (tag failed), or `Error: AES decryption failed: ...` (bad padding, wrong length, malformed base64), only when no mode decrypts it and the input is non-empty (an ECB-recovered `#` field keeps its value, with a one-line stderr `Warning: AES-GCM tag mismatch, read as legacy AES-ECB: ...`). Report via `cipher_aes_decrypt_{mode,base64}_report` (printf-style context); `blob_get_latest` peeks the cached version (`blob_peek_version`) and never parses a stale copy, so nothing is reported twice. Text form without a `!`/`#` marker is ECB only (no layout sniffing). The field is empty if nothing decrypts and flagged `*_undecrypted` (`struct account`, `struct field`; cleared by the setters); `account_require_decrypted` makes `duplicate`, `mv`, `edit`/`generate` on any secure note (also when the note itself is the flagged field, which expands to nothing) and `account_reencrypt` exit instead of rewriting such an account; `edit` of another account refuses only what the editor can't round-trip (`require_editable`: empty url saves as `http://`, empty name drops a decrypted group). `show`/`export` exit 1 when a requested field is flagged, mapped by `account_field_undecrypted` (`export` reports once per field, not per column; a secure note's username/password/url count as `note`). The blob still loads. A share that fails to load (`share_parse` NULL: RSA key, name, malformed chunk) is dropped with one stderr line, and `blob_parse` skips its `ACCT`/`ACFL`/`ACOF`/`AACT`/`AACF` chunks up to the next `SHAR`, so they are never decrypted with the user key or treated as personal. `error_msg` and `warning_msg` replace C0/DEL, UTF-8 C1 and bidi/line-separator chars: field names are writable by shared folder members. Other sites (attachments, share name, private key, `lpass passwd`) use the same helpers. Private key (`cipher_decrypt_private_key`) accepts `#` (v3) and `!` (v2).
- **Read fallback:** the binary blob has no per-item mode flag, so legacy ECB values starting with `#` are ambiguous with GCM. Read order GCM → CBC → ECB is intentional cross-client behavior; don't drop the ECB fallback. Decryptable ECB `#` fields round-trip unchanged because the stored form is the one that decrypted.

**HTTP:** all server calls go through `http_post_lastpass*` (`http.c`); endpoints in `endpoints.c` (vault), `endpoints-login.c` (login/pwchange), `endpoints-share.c` (sharing).

**Config dir** (`config.c`): `$LPASS_HOME`, else XDG data/config/runtime dirs, else `~/.lpass`. Created `0700`.

## Conventions

- Tabs, width 4 (`.editorconfig`). New files carry the GPL header with the OpenSSL exception (copy from any `.c`).
- Memory/errors: `x*` allocators and `die*()` (exit on failure), `_cleanup_free_` / `_cleanup_fclose_` attribute cleanups, `list.h` intrusive lists (kernel style). Use `secure_clear*` on password buffers.
- Editor-based flows (`edit.c`) put temp files in RAM (`/dev/shm` on Linux, ramdisk on macOS).
- Never log secrets. `LPASS_LOG_LEVEL` 8 (verbose) enables curl verbose output, which writes the session cookie to `lpass.log`.
- Platform `#ifdef`s live in `agent.c` (peer creds), `process.c`, `clipboard.c`, `edit.c`; keep Linux, macOS, Cygwin, BSD paths working.
- Never commit automatically. Leave changes uncommitted unless the user explicitly asks for a commit; never push or open a PR unprompted.
- Commits need a DCO line: `Signed-off-by: Name <email>` (see `CONTRIBUTING`).

## Releases

Version comes from `git describe` via `LASTPASS-VERSION-GEN` (run at cmake configure time, writes gitignored `version.h`). A release commit bumps `DEF_VER` in `LASTPASS-VERSION-GEN`, plus `CHANGELOG.md` and `debian/changelog`.
