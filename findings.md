# Semgrep Findings

## What I ran

```bash
semgrep scan --config p/default --metrics=off \
  --exclude node_modules --exclude dist .
# then, spot-check for credentials:
semgrep scan --config p/secrets --metrics=off .
```

**Result: 3 findings (2 distinct issues), 0 secrets.** 404 rules ran over 153 git-tracked files.

| # | Rule | Location | Severity |
|---|------|----------|----------|
| 1 | `...path-join-resolve-traversal` (CWE-22) | `resources/content_blocking/get_unique_filter_selectors.ts:117` | WARNING |
| 2 | `...spawn-shell-true` (CWE-78) | `resources/content_blocking/utils.ts:98` | ERROR |
| 3 | `...detect-child-process` (CWE-78) | `resources/content_blocking/utils.ts:98` | ERROR |

All three are in the `resources/content_blocking` developer tooling, not in the shipped `src/` library.

---

## Finding 1 — `path.join` with `readdir` result (likely false positive)

`resources/content_blocking/get_unique_filter_selectors.ts:117`

```ts
await eachLineInFile(path.join(inputDirectory, directoryItem.name), (line) => {
```

**Why it fires:** Semgrep treats `directoryItem.name` (from `fs.readdir`) as untrusted. In reality names returned by `readdir` are direct children and can't contain a path separator, and `inputDirectory` is a constant derived from `__dirname`. There is no attacker-controlled path here, so CWE-22 isn't reachable.

**Options, in order of preference:**

1. **Suppress with justification** (appropriate for this case):

   ```ts
   // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
   await eachLineInFile(path.join(inputDirectory, directoryItem.name), (line) => {
   ```

2. **Defense in depth** — resolve and verify containment, which also makes intent explicit:

   ```ts
   const filePath = path.resolve(directoryPath, directoryItem.name)
   if (!filePath.startsWith(path.resolve(directoryPath) + path.sep)) {
     throw new Error(`Refusing to read outside ${directoryPath}`)
   }
   await eachLineInFile(filePath, (line) => { ... })
   ```

While you're in this function: it takes a `directoryPath` parameter but line 117 uses the module-level `inputDirectory` instead. That's a latent correctness bug worth fixing either way.

---

## Findings 2 & 3 — `spawn(..., { shell: true })` and dynamic command

`resources/content_blocking/utils.ts:98`

```ts
const child = spawn(command, [], { shell: true, ...options })
```

Its only caller is `resources/content_blocking/insert_filter_code.ts:28`:

```ts
await runCommand(`eslint --fix ${JSON.stringify(codeFile)}`)
```

`codeFile` is a hard-coded path, so this isn't exploitable through user input today. It is still worth removing: `shell: true` means any shell metacharacters in the repository path (e.g. a checkout at a directory containing `` `...` `` or `$(...)`, which JSON-string double quotes do not neutralize) would be executed. Both rules point at the same line.

**Recommended fix — drop `child_process` entirely** and call ESLint's Node API (`eslint` is already a devDependency, and ESLint 8 supports this):

```ts
import { ESLint } from 'eslint'

// in run():
const eslint = new ESLint({ fix: true })
const results = await eslint.lintFiles([codeFile])
await ESLint.outputFixes(results)
```

Then delete `runCommand` from `utils.ts`, remove the `child_process` import, and drop the `insert_filter_code.ts` import. This removes both findings at the root.

**If you'd rather keep `runCommand`**, make it shell-free and pass arguments explicitly:

```ts
export function runCommand(
  command: string,
  args: readonly string[] = [],
  options: SpawnOptions = {},
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { ...options, shell: false })
    // ...
```

```ts
await runCommand(process.platform === 'win32' ? 'eslint.cmd' : 'eslint', ['--fix', codeFile])
```

Note `shell: false` needs the platform-specific executable name on Windows.

---

## Suggested follow-up

- **Keep `p/default` in CI** (e.g. a `.github/workflows/semgrep.yml` step) so new findings fail the build.
- **Deduplicate rule noise** if you don't plan to fix the dev scripts immediately: add a `.semgrepignore` entry for `resources/content_blocking/`, or use targeted `nosemgrep` comments as shown. Prefer the comments over a blanket ignore, so other findings in that directory still surface.
- **Caveat:** a handful of rules in `p/default` (`crypto-js`, `express`/`koa` CORS) errored out with *"metavariable-name:module(s) operator is only supported in the Pro engine"*. Those are Semgrep engine limitations, not findings, but it means the scan isn't 100% complete. Running with a Semgrep Pro license (or removing those rules from the config) would close that gap.
