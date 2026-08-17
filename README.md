# dsh-bugbounty-toolkit 🎯

Keyless bug-bounty recon & finding toolkit — a set of **DSH (deepseek-harness) plugins** plus an **OpenCode adapter**, packaged for one-click install.

- **100% keyless** — no API keys for any data source: crt.sh, HackerTarget, Wayback CDX, Tavily keyless mode.
- **3 DSH plugins**: `dsh-bugbounty` (9 `bb_*` tools), `dsh-opencode-search` (keyless web-search provider `tavily-keyless`), `dsh-nixon-hud` (in-browser plugins/state HUD for the DSH web GUI).
- **OpenCode adapter** (`opencode/bugbounty.js`): registers all 9 `bb_*` tools + `bb_web_search` for [opencode](https://opencode.ai/docs/plugins).

## Install (one click)

```bash
git clone https://github.com/Nixon-H/dsh-bugbounty-toolkit.git
cd dsh-bugbounty-toolkit
./install.sh --restart            # DSH web profile: copies plugins + patches cordis.patch.yml + restarts
./install-opencode.sh             # optional: OpenCode adapter (global config)
```

`install.sh` is idempotent — safe to re-run (re-copies plugin files, only adds missing `cordis.patch.yml` insert entries). Custom profile dir:

```bash
DSH_PROFILE_DIR=~/.dsh/profiles/web ./install.sh
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
plugins/dsh-bugbounty/        # DSH plugin: 9 bb_* tools + bbApi export
plugins/dsh-opencode-search/  # DSH plugin: tavily-keyless search provider + searchApi export
plugins/dsh-nixon-hud/        # DSH plugin: web GUI plugins/state HUD
opencode/bugbounty.js         # OpenCode adapter (10 tools)
tools/patch_cordis.py         # idempotent cordis.patch.yml patcher
install.sh                    # DSH one-click installer
install-opencode.sh           # OpenCode installer
docs/bughunt-templates/       # obsidian notebook templates from the research
```

## How it works

- **DSH**: the plugin dirs drop into `~/.dsh/profiles/<profile>/node_modules/`; `cordis.patch.yml` gets `- insert:` entries (`bugbounty` / `opencode-search` / `nixon-hud`). All sources are keyless & rate-limited — every tool collects per-source errors and fails gracefully.
- **OpenCode**: `bugbounty.js` dynamically imports the vendor libs (global config layout first, repo layout as fallback) and registers each `bb_*` tool with `tool.schema`-defined args. Needs `@opencode-ai/plugin` in `~/.config/opencode/package.json` (installer ensures it; opencode runs `bun install` at startup).

## Uninstall

- DSH: remove the three `- id:` blocks from `cordis.patch.yml` and delete the plugin dirs from `node_modules/`.
- OpenCode: delete `~/.config/opencode/plugins/bugbounty.js` and `~/.config/opencode/vendor/`.

## License

MIT — see [LICENSE](LICENSE).