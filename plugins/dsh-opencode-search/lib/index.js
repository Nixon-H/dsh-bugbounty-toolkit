/**
 * Keyless web search for dsh, embedded from opencode's zero-config path.
 *
 * opencode's beta web-search providers (Tavily / Exa / Parallel / Firecrawl)
 * use "keyless" API access instead of per-user API keys; Tavily's keyless mode
 * is `POST https://api.tavily.com/search` with the header
 * `X-Tavily-Access-Mode: keyless` and NO api_key anywhere. This plugin mounts
 * that exact endpoint as a dsh search provider, so web_search works with zero
 * credentials and zero keys.
 *
 * Registered under `ctx.web` as provider id `tavily-keyless`. The web profile's
 * cordis.patch.yml selects it via the `web` row's `config.searchProvider` (and
 * disables the API-key `web-search-deepseek` row), so no keyed provider runs.
 */
export const name = "opencode-search";
export const inject = ["web"];

const TAVILY_SEARCH_URL = "https://api.tavily.com/search";
const KEYLESS_HEADER = "X-Tavily-Access-Mode";
const DEFAULT_MAX_RESULTS = 8;

async function tavilyKeylessSearch(query, maxResults, signal) {
	const body = {
		query,
		max_results: maxResults ?? DEFAULT_MAX_RESULTS,
		search_depth: "basic",
		include_answer: false,
	};
	const response = await fetch(TAVILY_SEARCH_URL, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			[KEYLESS_HEADER]: "keyless",
		},
		body: JSON.stringify(body),
		signal,
	});
	const text = await response.text();
	let data = null;
	try {
		data = JSON.parse(text);
	} catch {
		data = null;
	}
	if (!response.ok) {
		const detail = data && data.detail ? ` — ${data.detail}` : "";
		throw new Error(`Tavily keyless search failed (HTTP ${response.status})${detail}`);
	}
	const sources = (data && Array.isArray(data.results) ? data.results : [])
		.filter((result) => result && typeof result.url === "string" && result.url.length > 0)
		.map((result) => ({
			url: result.url,
			...(result.title ? { title: result.title } : {}),
			...(result.content ? { snippet: result.content } : {}),
			...(result.published_date ? { publishedAt: result.published_date } : {}),
		}));
	return { sources, truncated: false };
}

export function apply(ctx) {
	ctx.web.registerSearchProvider({
		id: "tavily-keyless",
		available: () => true,
		search: (request, signal) => tavilyKeylessSearch(request.query, request.maxResults, signal),
	});
}

// Neutral API for reuse from non-DSH hosts (e.g. the OpenCode adapter).
export const searchApi = {
	name: "tavily-keyless",
	search: (query, maxResults, signal) => tavilyKeylessSearch(query, maxResults, signal),
};