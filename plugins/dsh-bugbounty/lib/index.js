// dsh-bugbounty — keyless bug bounty recon & finding toolkit for DSH.
// Zero-import pure ESM: no @deepseek-ai/* imports; global fetch/AbortController
// only. Registers 9 `bb_*` tools (enum, probe, headers, tech, wayback, recon,
// checklist, source-audit, triage) plus methodology guidance at systemPrompt
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
			"List apex DNS records: MX, TXT (SPF/DMARC), NS, CNAME dangling candidates"
		],
		techniques: ["bb_enum_subdomains", "bb_wayback_urls", "crt.sh", "HackerTarget", "RDAP/whois"]
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
			"Check http vs https: hosts reachable only over http often bypass HSTS/CSP"
		],
		techniques: ["bb_probe_http", "bb_recon", "ffuf", "dirsearch", "katana"]
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
			"Test HTTP method confusion: PUT/DELETE on GET-only endpoints, X-HTTP-Method-Override"
		],
		techniques: ["bb_wayback_urls (find id params)", "burp auth analyzer", "role swap", "method override"]
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
			"Authentication bypass: default/debug creds, X-Forwarded-For / X-Original-URL bypass, cookie deletion, path normalization (/admin, /./admin, /%2e%2e/)"
		],
		techniques: ["bb_security_headers", "jwt_tool", "hashcat", "host header injection"]
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
			"Escalate: steal tokens via injected JS, keylogging, CSRF token theft"
		],
		techniques: ["bb_wayback_urls (find params)", "burp collaborator", "XSS hunter", "CSP evaluator"]
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
			"Report impact: phishing, cookie scope, SEO poisoning"
		],
		techniques: ["bb_enum_subdomains", "dig CNAME", "nuclei takeover templates", "can-i-take-over-xyz"]
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
		description: "Bug bounty methodology checklist (14 categories: recon, IDOR/BAC, SSRF, auth, XSS, SQLi, business logic, API misconfig, subdomain takeover, CSRF/open redirect, file upload, engagement, reporting). For source-code audit use bb_source_audit(language?). Unfiltered returns a compact index; pass a category slug/name for full checks and techniques.",
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
	"- bb_checklist(category?) — web/API bug-bounty methodology checklist (14 categories: recon, IDOR/BAC, SSRF, auth, XSS, SQLi, business logic, API misconfig, subdomain takeover, CSRF/open redirect, file upload, engagement, reporting). Unfiltered = compact index; pass a slug/name (e.g. \"ssrf\", \"api\") for full checks + techniques.",
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