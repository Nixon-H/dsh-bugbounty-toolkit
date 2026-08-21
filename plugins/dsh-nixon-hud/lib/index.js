export const name = "nixon-hud";
export const inject = ["webServer", "loader"];

const FIBER_PHASE = ["pending", "loading", "active", "failed", null, "unloading"];

export function apply(ctx) {
  // Host half: expose a read-only snapshot of the Cordis loader entry table
  // at /plugins/state so the browser HUD can render real enabled/disabled
  // state for ungrouped rows (grouped entries are host-internal), not just
  // the client graph.
  ctx.effect(() => {
    const dispose = ctx.webServer.register({
      kind: "exact",
      path: "/plugins/state",
      handler: (req, res) => {
        if (req.method !== "GET" && req.method !== "HEAD") {
          res.writeHead(405, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "method not allowed" }));
          return;
        }
        try {
          const entries = [];
          for (const entry of ctx.loader.entries()) {
            if (entry.options && entry.options.group) continue;
            entries.push({
              id: entry.id,
              name: (entry.options && entry.options.name) || entry.id,
              enabled: !entry.disabled,
              phase:
                entry.fiber === void 0 ? null : (FIBER_PHASE[entry.fiber.state] ?? null),
            });
          }
          res.writeHead(200, {
            "content-type": "application/json",
            "cache-control": "no-store",
          });
          res.end(JSON.stringify({ entries }));
        } catch (error) {
          if (!res.headersSent) {
            res.writeHead(500, { "content-type": "application/json" });
          }
          res.end(JSON.stringify({ error: error && error.message ? error.message : String(error) }));
        }
      },
    });
    return () => dispose();
  }, "nixon-hud: /plugins/state");
}
