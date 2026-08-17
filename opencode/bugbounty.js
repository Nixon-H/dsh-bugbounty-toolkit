// dsh-bugbounty-toolkit — OpenCode adapter.
//
// Registers all 28 `bb_*` recon/finding tools from dsh-bugbounty plus a
// keyless web search tool (Tavily keyless mode, no API key).
//
// Install locations:
//   global : ~/.config/opencode/plugins/bugbounty.js
//            (vendor libs copied to ~/.config/opencode/vendor/<pkg>/lib/)
//   repo   : opencode/bugbounty.js  (falls back to ../../plugins/...)
//
// Requires `@opencode-ai/plugin` in the opencode config dir package.json —
// opencode runs `bun install` at startup (see install-opencode.sh).

import { tool } from "@opencode-ai/plugin";

const LIB_CANDIDATES = {
  bounty: [
    "../vendor/dsh-bugbounty/lib/index.js",          // installed global layout
    "./vendor/dsh-bugbounty/lib/index.js",            // config-dir variant
    "../../plugins/dsh-bugbounty/lib/index.js",       // repo layout (opencode/ -> plugins/)
    "../../../plugins/dsh-bugbounty/lib/index.js",    // nested project layout
  ],
  search: [
    "../vendor/dsh-opencode-search/lib/index.js",
    "./vendor/dsh-opencode-search/lib/index.js",
    "../../plugins/dsh-opencode-search/lib/index.js",
    "../../../plugins/dsh-opencode-search/lib/index.js",
  ],
};

async function loadModule(candidates) {
  for (const rel of candidates) {
    try {
      const mod = await import(new URL(rel, import.meta.url).href);
      if (mod && Object.keys(mod).length > 0) return mod;
    } catch {
      // try next candidate
    }
  }
  throw new Error("dsh-bugbounty-toolkit: vendor lib not found (run install-opencode.sh)");
}

// --- args schemas per bb tool (keyed by bb tool name) ---
const TOOL_ARGS = {
  bb_enum_subdomains: {
    domain: tool.schema.string().describe("Root domain, e.g. example.com (no scheme, no path)"),
  },
  bb_probe_http: {
    host: tool.schema.string().describe("Hostname or IP to probe (no scheme, no path)"),
    ports: tool.schema.array(tool.schema.number()).optional().describe("Optional ports to probe (default 80,443)"),
  },
  bb_security_headers: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_tech_detect: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_wayback_urls: {
    domain: tool.schema.string().describe("Domain to query, e.g. example.com"),
    limit: tool.schema.number().optional().describe("Max archived URLs (default 300, cap 2000)"),
  },
  bb_recon: {
    domain: tool.schema.string().describe("Root domain, e.g. example.com"),
  },
  bb_checklist: {
    category: tool.schema.string().optional().describe("Optional category slug (e.g. ssrf, api, idor)"),
  },
  bb_source_audit: {
    language: tool.schema.string().optional().describe("Optional language slug (c, cpp, rust, go, js, ts)"),
  },
  bb_triage: {},
  bb_actuator_scan: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_js_secrets: {
    domain: tool.schema.string().describe("Domain to query, e.g. example.com"),
    limit: tool.schema.number().optional().describe("Max JS bundles to mine (default 30)"),
  },
  bb_403_bypass: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_origin_ip: {
    domain: tool.schema.string().describe("Root domain, e.g. example.com"),
  },
  bb_crlf_scan: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_swagger_scan: {
    domain: tool.schema.string().describe("Domain to query, e.g. example.com"),
  },
  bb_s3_probe: {
    domain: tool.schema.string().describe("Domain to derive bucket names from, e.g. example.com"),
  },
  bb_punycode_gen: {
    email: tool.schema.string().describe("Email to generate variants from (e.g. admin@example.com)"),
    cap: tool.schema.number().optional().describe("Max homograph variants (default 18)"),
  },
  bb_mass_assign_gen: {},
  bb_email_payloads: {
    email: tool.schema.string().optional().describe("Optional email to embed in payloads"),
  },
  bb_nextjs_cve: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_ct_fresh_assets: {
    domain: tool.schema.string().describe("Domain to query, e.g. example.com"),
    limit: tool.schema.number().optional().describe("Max fresh assets to return (default 30)"),
  },
  bb_wordpress_surf: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_cache_deception_scan: {
    domain: tool.schema.string().describe("Domain to query, e.g. example.com"),
    limit: tool.schema.number().optional().describe("Max archived URLs to scan (default 600, cap 2000)"),
  },
  bb_sqli_param_hunt: {
    domain: tool.schema.string().describe("Domain to query, e.g. example.com"),
    limit: tool.schema.number().optional().describe("Max endpoints to rank (default 300)"),
  },
  bb_waf_fingerprint: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_cors_scan: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_git_exposure: {
    url: tool.schema.string().describe("Full URL starting with http:// or https://"),
  },
  bb_sensitive_files: {
    domain: tool.schema.string().describe("Domain to mine, e.g. example.com"),
    limit: tool.schema.number().optional().describe("Max URLs to return (default 60)"),
  },
};

// --- compact renderer: structured bb results -> flat text for the model ---
function formatResult(v, depth = 0) {
  if (v == null) return String(v);
  const t = typeof v;
  if (t === "string" || t === "number" || t === "boolean") return String(v);
  if (Array.isArray(v)) {
    return v.map((x) => formatResult(x, depth + 1)).join("\n");
  }
  if (t === "object") {
    const parts = [];
    for (const [k, val] of Object.entries(v)) {
      if (val == null) {
        parts.push(`${k}: ${String(val)}`);
      } else if (Array.isArray(val)) {
        parts.push(`${k} (${val.length}):\n${val.map((x) => "  " + formatResult(x, depth + 1)).join("\n")}`);
      } else if (typeof val === "object") {
        parts.push(`${k}: ${formatResult(val, depth + 1)}`);
      } else {
        parts.push(`${k}: ${String(val)}`);
      }
    }
    const out = parts.join("\n");
    return out.length > 12000 ? out.slice(0, 12000) + "\n...[truncated]" : out;
  }
  return String(v);
}

export const bugbounty = async () => {
  const bountyMod = await loadModule(LIB_CANDIDATES.bounty);
  const searchMod = await loadModule(LIB_CANDIDATES.search);
  const { bbApi } = bountyMod;
  const { searchApi } = searchMod;

  const tools = {};
  for (const [name, def] of Object.entries(bbApi)) {
    tools[name] = tool({
      description: def.description,
      args: TOOL_ARGS[name] ?? {},
      async execute(args) {
        try {
          const res = await def.execute(args ?? {});
          return formatResult(res);
        } catch (err) {
          return `error: ${err && err.message ? err.message : String(err)}`;
        }
      },
    });
  }

  tools.bb_web_search = tool({
    description: "Keyless web search (Tavily keyless mode, no API key required). Returns results with source URLs.",
    args: {
      query: tool.schema.string().describe("Search query"),
      max_results: tool.schema.number().optional().describe("Max results (default 8)"),
    },
    async execute(args) {
      try {
        const res = await searchApi.search(args.query, args.max_results ?? 8);
        return formatResult(res);
      } catch (err) {
        return `error: ${err && err.message ? err.message : String(err)}`;
      }
    },
  });

  return { tool: tools };
};

export default bugbounty;