# dsh-bugbounty-toolkit 🎯

Keyless bug-bounty recon & finding toolkit for the **DeepSeek Harness (DSH web)** — with an **optional OpenCode adapter**.

`install.sh` is a **one-click full-profile clone**: it installs *everything currently live* in the DSH profile — the 3 custom plugins, the complete `cordis.patch.yml` (all tool/plugin re-enables + keyless search provider), the keyless deepseek provider settings, and the web-search bridge.

- **100% keyless** — no API keys for any data source: crt.sh, HackerTarget, Wayback CDX, Tavily keyless mode.
- **3 DSH plugins**: `dsh-bugbounty` (9 `bb_*` tools), `dsh-opencode-search` (keyless web-search provider `tavily-keyless`), `dsh-nixon-hud` (in-browser plugins/state HUD for the DSH web GUI).
- **OpenCode adapter** (`opencode/bugbounty.js`): registers all 9 `bb_*` tools + `bb_web_search` for [opencode](https://opencode.ai/docs/plugins) — **optional**.

## Install — one click for DSH web (the harness)

```bash
git clone https://github.com/Nixon-H/dsh-bugbounty-toolkit.git
cd dsh-bugbounty-toolkit
./install.sh --restart            # full profile clone + restart dsh web
```

That single command:

1. copies the **3 custom plugins** into `~/.dsh/profiles/web/node_modules/`;
2. installs the **full `cordis.patch.yml`** (all 23+ tool/plugin re-enables, `web` → `tavily-keyless` search provider, and the 3 plugin inserts). If a `cordis.patch.yml` already exists it is backed up to `cordis.patch.yml.bak.<timestamp>` first;
3. installs **`settings.yaml`** (keyless deepseek providers — only if you have none) and **`web-search-bridge.py`** (only if missing);
4. keeps any profile root files you already have (`cordis.yml`, `package.json`, `pnpm-workspace.yaml`).

Custom profile/home:

```bash
DSH_PROFILE_DIR=~/.dsh/profiles/myprofile ./install.sh --restart
```

The `--restart` flag restarts `dsh web` (the managed harness restarts it) so every plugin mounts immediately. Re-running is a safe no-op when the patch is already in place.

## Optional: OpenCode adapter

The OpenCode adapter is an extra — it is *not* needed for the DSH harness:

```bash
./install-opencode.sh             # OpenCode adapter (global config)
# or both in one:
./install.sh --restart --opencode
```

## Tools

### DSH (`dsh-bugbounty` — 9 tools)

| Tool | What it does |
|---|---|
| `bb_enum_subdomains(domain)` | Passive subdomain enum: crt.sh CT logs + HackerTarget |
| `bb_probe_http(host, ports?)` | Fast HTTP(S) liveness probe: status, title, Server banner |
| `bb_security_headers(url)` | Header audit: CSP/HSTS/XFO/XCTO/COOP/COEP + cookie flags + leaks |
| `bb_tech_detect(url)` | Tech fingerprint from headers, cookies, HTML |
| `bb_wayback_urls(domain, limit?)` | Wayback CDX mining; flags interesting endpoints/params |
| `bb_recon(domain)` | One-shot pipeline: enum → probe → tech detect → header audit |
| `bb_checklist(category?)` | Web/API bug-bounty methodology — 14 categories |
| `bb_source_audit(language?)` | Segregated source-code audit methodology (C/C++/Rust/Go/JS/TS) |
| `bb_triage()` | Rhat-scored bug triage: P(real)/P(feasible)/P(reproducible)/P(new RC)/impact → REPORT / INVESTIGATE / DISCARD |

### DSH (`dsh-opencode-search`)
- Registers web-search provider `tavily-keyless` (Tavily keyless mode, no API key) for the DSH `web` tool.

### OpenCode
- `bb_enum_subdomains`, `bb_probe_http`, `bb_security_headers`, `bb_tech_detect`, `bb_wayback_urls`, `bb_recon`, `bb_checklist`, `bb_source_audit`, `bb_triage`, `bb_web_search`.

## What's inside / merge map

Built from the last-night bughunt research (everything merged into plugin code):

| Bughunt artifact | Lives now in |
|---|---|
| `rules/bug-bounty.md` | `bb_checklist` (14 categories: recon, IDOR/BAC, SSRF, auth, XSS, SQLi, business logic, API misconfig, subdomain takeover, CSRF/open redirect, file upload, engagement, reporting…) |
| `rules/source-audit.md` | `bb_source_audit` (7-step audit flow, per-language checks + grep patterns) |
| `rules/shell-strategy.md` | Engagement/ops guidance (scope-first, 24h disclosure) |
| `obsidian-templates/bug-report.md` + `FINDINGS.md` (SQLite audit, verdict classes) | `bb_triage` |
| `obsidian-templates/*.md` (campaign, target, entity, source, concept, question, research-notebook, dashboard, comparison) | `docs/bughunt-templates/` |

## Repo layout

```
config/dsh-profile/           # live-profile snapshot (byte-identical clones)
  cordis.patch.yml            #   full patch: re-enables + tavily-keyless + 3 inserts
  settings.yaml               #   keyless deepseek providers (env-var names only — no keys)
  web-search-bridge.py        #   optional web-search-deepseek bridge
  cordis.yml / package.json / pnpm-workspace.yaml   # profile root files
plugins/dsh-bugbounty/        # DSH plugin: 9 bb_* tools + bbApi export
plugins/dsh-opencode-search/  # DSH plugin: tavily-keyless search provider + searchApi export
plugins/dsh-nixon-hud/        # DSH plugin: web GUI plugins/state HUD
opencode/bugbounty.js         # OpenCode adapter (10 tools) — optional
tools/patch_cordis.py         # advanced: idempotent cordis.patch.yml patcher (optional utility)
install.sh                    # DSH one-click full-profile installer
install-opencode.sh           # OpenCode installer (optional)
docs/bughunt-templates/       # obsidian notebook templates from the research
```

## How it works

- **DSH**: the installer drops the plugin dirs into `~/.dsh/profiles/<profile>/node_modules/` and installs the full `cordis.patch.yml` so every plugin (built-in and custom) mounts exactly as in the source profile. All sources are keyless & rate-limited — every tool collects per-source errors and fails gracefully.
- **OpenCode**: `bugbounty.js` dynamically imports the vendor libs (global config layout first, repo layout as fallback) and registers each `bb_*` tool with `tool.schema`-defined args. Needs `@opencode-ai/plugin` in `~/.config/opencode/package.json` (installer ensures it; opencode runs `bun install` at startup).

## Uninstall

- DSH: remove the three `- id:` blocks from `cordis.patch.yml` (or restore your `cordis.patch.yml.bak.<timestamp>`) and delete the plugin dirs from `node_modules/`.
- OpenCode: delete `~/.config/opencode/plugins/bugbounty.js` and `~/.config/opencode/vendor/`.

## License

MIT — see [LICENSE](LICENSE).
