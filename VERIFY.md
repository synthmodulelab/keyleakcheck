# Verify the guarantees yourself

Don't take our word for it. Each check below takes under a minute.

## 1. It makes no network connections (Linux)

Trace every network system call during a full scan:

```sh
strace -f -qq -e trace=socket,connect,sendto,sendmsg,bind -o net.trace npx keyleakcheck >/dev/null
wc -l net.trace   # expected: 0
```

To confirm the trace works, run it on something that does use the network: `strace -f -e trace=connect node -e "require('net').connect(9,'127.0.0.1').on('error',()=>{})"` shows `connect` calls.

On macOS you can watch with Little Snitch or LuLu, or run the scan with Wi-Fi off: the result is identical.

## 2. It never writes, changes or deletes a file

Run it under the Node.js permission model (Node 22+), which allows reading and blocks every write, child process and worker:

```sh
node --permission --allow-fs-read="*" "$(npm root -g)/keyleakcheck/bin/keyleakcheck.js"
```

Or from a clone: `node --permission --allow-fs-read="*" bin/keyleakcheck.js`. If the tool tried to write a file, it would stop with `ERR_ACCESS_DENIED`.

On Linux you can also trace file system calls:

```sh
strace -f -qq -e trace=openat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,truncate,chmod -o fs.trace npx keyleakcheck >/dev/null
grep -E 'O_WRONLY|O_RDWR|O_CREAT|unlink|rename|mkdir|truncate|chmod' fs.trace | grep -v /dev/   # expected: no output
```

## 3. It never prints a full key

```sh
npx keyleakcheck --json | grep -E 'sk-[A-Za-z0-9_-]{24,}|AIza[0-9A-Za-z_-]{20,}'   # expected: no output
```

## 4. It has no dependencies and no install scripts

```sh
npm view keyleakcheck dependencies scripts
```

## 5. The package you installed is the one built from this repo

Applies to releases published through `.github/workflows/release.yml`:

```sh
npm audit signatures
gh attestation verify keyleakcheck-<version>.tgz --repo synthmodulelab/keyleakcheck
```

## Every promise and the test that checks it

Every claim in the README, SECURITY.md and `--help` is checked automatically on every commit. A claim without a test is treated as a bug.

| Promise | Checked by |
| --- | --- |
| No network access | `guarantees`: no network modules, no `fetch`/`eval`; `coverage`: fetch tripwire installed first; CI `runtime-guarantees`: strace shows 0 network calls |
| Read-only | `guarantees`: fs allowlist and read-only `openSync`; `scan`: no file changes during a scan; CI: permission model and strace show 0 write calls |
| No full key in any output; masks show only the fixed prefix and last 4 | `scan`: text/JSON/card leak test and mask test |
| Card has no keys and no paths | `scan`: card test |
| Zero dependencies, no install scripts, only `bin/` and `src/` published | `guarantees` |
| Finds every supported key format, after any separator or escape, in UTF-8, UTF-16 and binary files, at any line length and read size, on the right line | `fuzz`: 400 random documents per run, 5,000 in CI, 168,000 in our own verification of the current code; 16 key formats |
| Ignores placeholders but keeps real keys of every shape | `scan` and `coverage`: placeholder tests, including real keys that contain words like "dumMy" by chance; entropy test over 80,000 random real-shaped keys |
| Large files are read, not skipped; anything not scanned is reported, marks the scan partial and exits with 3 | `scan`: chunk, max-file-mb and file-limit tests; `coverage`: unreadable-folder test |
| Home and root folders are not walked as a project | `scan` and `coverage` |
| `--path` to a missing folder is an error; to a file scans that file | `coverage` |
| `.keyleakcheckignore` and `--ignore` | `scan` |
| Control and bidi characters in file names cannot alter the report or JSON | `scan` and `coverage` |
| `.gitignore` judgement (folder rules, path rules, `**`, info/exclude, global excludes, negation) | `coverage` |
| Every documented location is scanned; env overrides honoured; symlinked agent folders followed; symlinked folders inside never followed | `coverage` and `scan` |
| Credential stores and `primaryApiKey` reported as low; Claude login tokens detected | `coverage` |
| Browser caches and expired temporary AWS keys reported as low, with an explanation; repeated hits grouped per file | `coverage` |
| `--list-locations` reads no file contents | `coverage` |
| Exit codes 0, 1, 2, 3 | `scan` and `coverage` |
| Piping into `head` prints no error | `coverage` |
| Source contains no invisible or bidi characters | `guarantees` |

Not automatable, measured by hand: speed (below), and that provider console links still work (checked against provider docs, October 2026).

## Results from our own verification (v0.1.0, Linux, Node 22)

| Check | Result |
| --- | --- |
| Test suite | 56 tests: 55 pass, 1 skipped as root (the unreadable-folder test). On a real Mac (Node 24, normal user) all tests passed |
| Randomised test, after the last change to the scanner | 168,000 documents, 0 failures |
| First run on a real Mac | Found Claude Code, Claude Desktop, Codex, Gemini CLI and VS Code; 2,825 files, complete scan, no permission prompts. Its two findings (a website's key in a browser cache, an expired temporary AWS key) led to the low-risk rules for browser caches and temporary AWS keys |
| Network system calls during a full scan | 0 (control program: 2) |
| File-write system calls during a full scan | 0 (control program: 1) |
| Scan under `--permission` with read-only access | Completed normally |
| `--list-locations` file opens inside the scanned folders | 0 |
| Masking fuzz: 100 random key sets × 3 output formats | 0 leaks of any 6-character run of a key body |
| False positives on about 8,250 real files (npm, four Python standard libraries, /usr/share, /etc) | 0. One real finding: a Google Maps API key hard-coded in a TeX Live script |
| Speed: 200 MB of agent transcripts, no keys | 1.7 s |
| Speed: 200 MB, worst case (every line contains `sk-`) | 5.9 s |
| 1 GB single transcript, key on the last line, heap capped at 256 MB | Found, correct line number |

These numbers come from one machine. CI repeats the test suite on Linux, macOS and Windows with Node 20, 22 and 24. Please report your own results.
