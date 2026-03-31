# axioscan

Local IOC scanner for the **axios / plain-crypto-js** npm supply-chain incident (March 2026).

`axioscan` walks a repository checkout and checks lockfiles, manifests, and installed `node_modules` for indicators of compromise tied to the malicious `plain-crypto-js` package that was briefly injected as a transitive dependency of `axios`.

## What it detects

| Status | Meaning | Examples |
|---|---|---|
| **compromised** | Concrete IOC found | `plain-crypto-js@4.2.0` or `4.2.1` resolved in a lockfile or installed; `axios` declaring `plain-crypto-js` as a dependency; loader-style payload indicators in JS files |
| **at-risk** | Unresolved exposure | `axios` declared in `package.json` but no lockfile or `node_modules` to verify; `axios@1.14.1` (the advisory version) referenced; `plain-crypto-js` declared directly |
| **no-evidence-found** | No IOC matched | Clean repository |

### Files inspected

- `package.json` (all dependency sections)
- `package-lock.json`, `npm-shrinkwrap.json` (lockfile v1 and v2/v3)
- `yarn.lock` (classic and berry)
- `pnpm-lock.yaml` (v5 and v6+)
- `bun.lock`, `bun.lockb`
- `node_modules/**/axios/package.json`
- `node_modules/**/plain-crypto-js/package.json`
- `plain-crypto-js` JS files (`execSync`, `os.tmpdir`, `renameSync`, etc.)

## Quick start

Clone and run directly — no package manager install needed.

```bash
git clone https://github.com/user/axioscan.git
cd axioscan

# Scan a target repo
cargo run -- /path/to/your/repo

# JSON output (for CI / scripting)
cargo run -- --json /path/to/your/repo
```

If you want a standalone binary:

```bash
cargo build --release
./target/release/axioscan /path/to/your/repo
```

> **Why not `cargo install`?**
> This is a supply-chain attack scanner. Installing it through a package manager would add the very kind of trust dependency you are trying to audit. Clone the repo, read the source — it's pure Rust with **zero external dependencies** — and build it yourself.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No evidence found |
| 1 | At-risk or unverifiable exposure |
| 2 | Compromise evidence detected |
| 3 | Scanner error |

Use exit codes in CI to gate deployments:

```bash
axioscan . || { echo "IOC detected"; exit 1; }
```

## Design decisions

- **Zero external dependencies.** The entire crate builds with only `std`. JSON parsing uses a built-in recursive-descent parser (`src/json.rs`) instead of serde, eliminating any supply-chain trust requirement beyond rustc itself.
- **Offline-only.** No registry queries. The scanner judges what exists locally, not what the registry currently serves.
- **Single-incident scope.** Tuned to the `axios` / `plain-crypto-js` IOCs. If the attack pivots to different package names or versions, the constants in `src/ioc.rs` need updating.

## Registry context

When this tool was built (March 30-31, 2026):

- `axios@1.14.1` was not present on the npm registry
- `axios` `latest` was `1.14.0`
- `plain-crypto-js` `4.2.0` and `4.2.1` were published on March 30, then replaced by a `0.0.1-security` placeholder by March 31

## License

MIT
