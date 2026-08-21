# dsh-bugbounty-toolkit 🎯

Keyless bug-bounty recon & finding toolkit for the **DeepSeek Harness (DSH web)** — with an **optional OpenCode adapter**.

`install.sh` is a **one-click full-profile clone**: it installs *everything currently live* in the DSH profile — the 3 custom plugins, the complete `cordis.patch.yml` (all tool/plugin re-enables + keyless search provider), the keyless deepseek provider settings, and the web-search bridge.

- **100% keyless** — no API keys for any data source: crt.sh, HackerTarget, Wayback CDX, Tavily keyless mode.
- **3 DSH plugins**: `dsh-bugbounty` (53 `bb_*` tools), `dsh-opencode-search` (keyless web-search provider `tavily-keyless`), `dsh-nixon-hud` (in-browser plugins/state HUD for the DSH web GUI).
- **OpenCode adapter** (`opencode/bugbounty.js`): registers all 53 `bb_*` tools + `bb_web_search` for [opencode](https://opencode.ai/docs/plugins) — **optional**.

## Install — one click for DSH web (the harness)

```bash
git clone https://github.com/Nixon-H/dsh-bugbounty-toolkit.git
cd dsh-bugbounty-toolkit
./install.sh --restart            # full profile clone + restart dsh web
```

That single command:

1. copies the **3 custom plugins** into `~/.dsh/profiles/web/node_modules/`;
2. installs the **full `cordis.patch.yml`** (all 23+ tool/plugin re-enables, `web` → `tavily-keyless` search provider, and the 3 plugin inserts). If a `cordis.patch.yml` already exists it is backed up to `cordis.patch.yml.bak.<timestamp>` first;
3. installs **`settings.yaml`** (keyless deepseek providers — only if you have none) and **`web-search-bridge.py`** (only if missing). **Note:** the shipped `settings.yaml` sets `permission.defaultPreset: danger-full-access` (no tool-approval prompts — intentional for this profile; edit it if you want approvals);
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

### DSH (`dsh-bugbounty` — 53 tools)

| Tool | What it does |
|---|---|
| `bb_enum_subdomains(domain)` | Passive subdomain enum: crt.sh CT logs + HackerTarget |
| `bb_probe_http(host, ports?)` | Fast HTTP(S) liveness probe: status, title, Server banner |
| `bb_security_headers(url)` | Header audit: CSP/HSTS/XFO/XCTO/COOP/COEP + cookie flags + leaks |
| `bb_tech_detect(url)` | Tech fingerprint from headers, cookies, HTML |
| `bb_wayback_urls(domain, limit?)` | Wayback CDX mining; flags interesting endpoints/params |
| `bb_recon(domain)` | One-shot pipeline: enum → probe → tech detect → header audit |
| `bb_checklist(category?)` | Web/API bug-bounty methodology — 90 categories |
| `bb_source_audit(language?)` | Segregated source-code audit methodology (C/C++/Rust/Go/JS/TS) |
| `bb_triage()` | Rhat-scored bug triage: P(real)/P(feasible)/P(reproducible)/P(new RC)/impact → REPORT / INVESTIGATE / DISCARD |
| `bb_actuator_scan(url)` | Spring Boot Actuator probes: /actuator/env, /heapdump, /jolokia, + path mutations |
| `bb_js_secrets(domain, limit?)` | Wayback CDX JS-bundle mining for AWS/Google keys + JWTs |
| `bb_403_bypass(url)` | 403 bypass battery: method flips, routing headers, path mutations |
| `bb_origin_ip(domain)` | Origin-IP hunt: SPF records + OTX passive DNS, then header/title confirm |
| `bb_crlf_scan(url)` | CRLF injection: %0d%0a, %00%0d%0a, GBK variants; detects injected Set-Cookie |
| `bb_swagger_scan(domain)` | OpenAPI/Swagger endpoint discovery (22 paths) |
| `bb_s3_probe(domain)` | Predictable S3 bucket probing: listable/open buckets |
| `bb_punycode_gen(email, cap?)` | Homograph + punycode email variants for IDN/punycode bugs |
| `bb_mass_assign_gen()` | Mass-assignment payloads: isAdmin/role/org/__proto__/$ne … (33) |
| `bb_email_payloads(email?)` | Email-field payloads: case/+alias/dot/CRLF/metadata SSRF/SQLi/CMDi/homograph |
| `bb_nextjs_cve(url)` | CVE-2025-29927: x-middleware-subrequest middleware bypass |
| `bb_ct_fresh_assets(domain, limit?)` | crt.sh CT-log JSON: freshest certs for new asset discovery |
| `bb_wordpress_surf(url)` | WordPress surf: REST user enum, xmlrpc.php, config backups, debug.log |
| `bb_cache_deception_scan(domain, limit?)` | Cache-deception scan: archived account URLs + static-extension suffixes |
| `bb_sqli_param_hunt(domain, limit?)` | Wayback+OTX endpoint mining → dynamic pages + SQLi-prone param ranking |
| `bb_waf_fingerprint(url)` | WAF fingerprint (Cloudflare/Akamai/Imperva/AWS/F5/Azure/Sucuri) + tamper hints |
| `bb_cors_scan(url)` | CORS misconfig: reflected ACAO, ACAC true, wildcard+credentials, missing Vary: Origin |
| `bb_git_exposure(url)` | Exposed .git probes: HEAD/config/index/logs/refs + directory listing |
| `bb_sensitive_files(domain, limit?)` | Wayback sensitive-file mining: .env/.sql/.bak/.key/.pem/... grouped by ext |
| `bb_ntlm_probe(url)` | NTLM Type-2 challenge parse: TargetName (domain), Server Challenge, AV_PAIRS |
| `bb_graphql_introspection(url)` | GraphQL introspection probes (8 endpoints): __schema query, type count + mutability |
| `bb_source_leak_scan(url, maps?)` | ~25 source/build leak paths: .env variants, .git, swagger, build-info + .js.map derivation |
| `bb_shadow_api(url, version_params?)` | Shadow-API hunt: /api/vN siblings + X-API-Version / Accept header versioning |
| `bb_soft404_check(url)` | Soft-404 false-positive killer: junk-path baseline vs suspected exposure |
| `bb_vpn_fingerprint(host)` | VPN appliance fingerprint: Cisco/Fortinet/Citrix/Palo Alto/Ivanti/SonicWall/F5 + CVE hints |
| `bb_dns_email_audit(domain)` | Email/DNS hardening via DoH: SPF breakdown, DMARC, CAA, MTA-STS, DKIM selectors |
| `bb_entra_tenant_probe(domain, user?)` | M365/Entra tenant fingerprint: getuserrealm.srf Managed/Federated + autodiscover |
| `bb_cache_key_probe(url, headers?)` | CDN cache-key test: unkeyed X-Forwarded-Host/URL headers → cache poisoning signal |
| `bb_ratelimit_classify(url)` | Rate-limit posture: no-limit / soft 429 / lockout / suspicious (2 small bursts) |
| `bb_nosqli_auth_probe(url)` | NoSQL auth-bypass probes: $ne/$gt/$regex, array wrap, __proto__ (authorized targets only) |
| `bb_jwt_analyze(token)` | Local JWT decode/audit: alg:none, empty sig, kid/jku/x5u surface, exp, privilege/x-hasura claims (pure compute) |
| `bb_cloud_storage_scan(domain)` | Open/listable Azure Blob, GCP Storage, Firebase RTDB bucket probing (GET-only) |
| `bb_psbdmp_search(query)` | Keyless paste-dump search (psbdmp.ws, 33 archives) for leaked creds/secrets (authorized targets only) |
| `bb_dockerhub_search(org)` | Docker Hub API recon: org repos + latest tags — internal images, secrets in layers, abandoned orgs |
| `bb_dangling_cname(domain)` | Dangling CNAME hunt: crt.sh subs → DoH CNAME → NXDOMAIN → third-party takeover services |
| `bb_dns_wildcard_probe(domain)` | Wildcard DNS detection: random-label DoH resolves, identical IP sets = wildcard (enum false-positive killer) |
| `bb_resurrected_endpoints(domain)` | Wayback-mined deleted/forgotten endpoints probed live — resurrected admin/API paths often lack auth (authorized only) |
| `bb_api_docs_diff(domain)` | Live OpenAPI spec vs newest Wayback snapshot: removed/shadow + newly exposed endpoints |
| `bb_h1_intel(handle?)` | Best-effort HackerOne scope intel (policy_scopes JSON / public programs index) for scope verification |
| `bb_idor_extract(request)` | Parse a raw HTTP request/URL and list field-name-aware candidate ID fields (query/path/matrix/JSON/XML/Bearer) — idor-tester-ai port, pure local compute |
| `bb_idor_boundary_gen(id, key?)` | Generate a deterministic ID boundary battery (0, -1, 999999999, +1/-1, UUID mutations, empty/null, removal) — idor-tester-ai port, pure local compute |
| `bb_idor_swap_probe(url, attacker_id, victim_id)` | IDOR/BOLA swap probe: baseline + attacker→victim ID-swapped requests scored CONFIRMED/HIGH/MEDIUM/LOW (authorized targets only, heuristic leads) |
| `bb_xss_probe(url, param?)` | Reflected-XSS quick probe: marker injection per query param, echo-context detection (raw/attr/in-script/encoded) (authorized targets only) |
| `bb_ssrf_probe(url, param?)` | SSRF quick probe: overwrite params with loopback + AWS/GCP IMDS URLs, status/body-diff detection (authorized targets only) |

### DSH (`dsh-opencode-search`)
- Registers web-search provider `tavily-keyless` (Tavily keyless mode, no API key) for the DSH `web` tool.

### OpenCode
- All 53 `bb_*` tools (see table above) + `bb_web_search`.

## What's inside / merge map

Built from the last-night bughunt research (everything merged into plugin code):

| Bughunt artifact | Lives now in |
|---|---|
| `rules/bug-bounty.md` | `bb_checklist` (90 categories: 24 core categories — recon, IDOR/BAC, SSRF, auth, XSS, SQLi, business logic, API misconfig, subdomain takeover, CSRF/open redirect, file upload, engagement, reporting, registration-flows + 26 article-derived categories: actuator, js-recon, origin-ip, crlf, host-header, rate-limit, 403-bypass, email-field, mass-assignment, punycode, blind-xss, waf-bypass, framework-cves, github-recon, iis-fuzzing, nuclei-dast, s3-recon, swagger, wayback-mining, fuzz-pipeline, sqli-recon, open-redirect, cache-deception, wordpress, ct-monitor, url-collection + 5 cheat-sheet categories: sensitive-data, lfi, cors, google-dorks, … + 30 new: ssti-injection, xxe-injection, deserialization, jwt-attacks, graphql, http-smuggling, race-condition, nosql-injection, ldap-injection, oauth-sso, mfa-2fa-bypass, captcha-bypass, password-reset-flaw, session-management, source-leak, shadow-api, ntlm-info, grpc, websocket, dom-attacks, prototype-pollution, cache-poisoning, llm-ai, mobile-app, cloud-misconfig, k8s-docker, enterprise-platforms, cicd-supply-chain, web3-audit, offensive-osint + 5 sync-added: leak-monitoring, bug-chaining, fuzzing-0day, timing-xsleaks, client-apps; later rounds added second-order-injection, dos-resource-exhaustion, hash-archive-cracking, idp-confusion, windows-lpe, fix-bypass-retest, formal-verification, gas-qa-audit, c-cpp, rust, go, js-ts) |
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
plugins/dsh-bugbounty/        # DSH plugin: 53 bb_* tools + bbApi export
plugins/dsh-opencode-search/  # DSH plugin: tavily-keyless search provider + searchApi export
plugins/dsh-nixon-hud/        # DSH plugin: web GUI plugins/state HUD
opencode/bugbounty.js         # OpenCode adapter (54 tools: 53 bb_* + bb_web_search) — optional
tools/patch_cordis.py         # advanced: idempotent cordis.patch.yml patcher (optional utility)
install.sh                    # DSH one-click full-profile installer
install-opencode.sh           # OpenCode installer (optional)
docs/bughunt-templates/       # obsidian notebook templates from the research
docs/articles/                # methodology-article URL lists (texts/ is gitignored — copyright; fetch via the URL lists)
```

## How it works

- **DSH**: the installer drops the plugin dirs into `~/.dsh/profiles/<profile>/node_modules/` and installs the full `cordis.patch.yml` so every plugin (built-in and custom) mounts exactly as in the source profile. All sources are keyless & rate-limited — every tool collects per-source errors and fails gracefully.
- **OpenCode**: `bugbounty.js` dynamically imports the vendor libs (global config layout first, repo layout as fallback) and registers each `bb_*` tool with `tool.schema`-defined args. Needs `@opencode-ai/plugin` in `~/.config/opencode/package.json` (installer ensures it; opencode runs `bun install` at startup).

## Uninstall

- DSH: remove the three `- id:` blocks from `cordis.patch.yml` (or restore your `cordis.patch.yml.bak.<timestamp>`) and delete the plugin dirs from `node_modules/`.
- OpenCode: delete `~/.config/opencode/plugins/bugbounty.js` and `~/.config/opencode/vendor/`.

## License

MIT — see [LICENSE](LICENSE).
