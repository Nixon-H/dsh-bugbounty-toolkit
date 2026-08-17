window.__ModuleLoader__.load({
	id: "dsh-nixon-hud",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;

		// -----------------------------------------------------------------
		// NIXON HUD — zero-dependency status widget for the DSH web shell.
		// Bottom-right, collapsible, draggable; dies silently on any failure.
		// -----------------------------------------------------------------
		const TAGS = [
			"red team on duty",
			"ostentatious minimalism",
			"the ui is a vibe",
			"no deps were harmed",
			"view source, live fast",
			"stealth > spam",
		];
		const POS_KEY = "dsh-nixon-hud-pos";

		function bootInfo() {
			try {
				const b = window.__DSH_BOOT__;
				return b && Array.isArray(b.entries) ? b : null;
			} catch (e) {
				return null;
			}
		}

		function fmt(deltaMs) {
			const s = Math.floor(deltaMs / 1000);
			const h = String(Math.floor(s / 3600)).padStart(2, "0");
			const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
			const sec = String(s % 60).padStart(2, "0");
			return h === "00" ? `${m}:${sec}` : `${h}:${m}:${sec}`;
		}

		function apply(ctx) {
			try {
				const doc = document;
				const host = location.hostname;
				const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1";

				const style = doc.createElement("style");
				style.id = "dsh-nixon-hud-style";
				style.textContent = `
#dsh-nixon-hud{position:fixed;right:12px;bottom:12px;z-index:2147483000;
  font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#c9d6cf;
  background:rgba(8,10,14,.55);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  border:1px solid rgba(120,170,150,.35);border-radius:8px;padding:6px 10px;
  box-shadow:0 4px 18px rgba(0,0,0,.35);user-select:none;min-width:210px;max-width:340px}
#dsh-nixon-hud .nh-head{display:flex;align-items:center;gap:6px;cursor:grab;
  font-weight:700;letter-spacing:.12em;color:#7dd3a8;white-space:nowrap}
#dsh-nixon-hud .nh-head:active{cursor:grabbing}
#dsh-nixon-hud .nh-head .nh-chev{color:#6b7c74;font-size:9px}
#dsh-nixon-hud .nh-body{margin-top:5px;display:grid;grid-template-columns:auto 1fr;
  gap:1px 10px;opacity:.92}
#dsh-nixon-hud .nh-body .k{color:#6b7c74}
#dsh-nixon-hud .nh-body .v{text-align:right;white-space:nowrap}
#dsh-nixon-hud .nh-body .v.click{cursor:pointer}
#dsh-nixon-hud .nh-body .v.click:hover{color:#9dd8ba}
#dsh-nixon-hud .nh-live{color:#6fe39a}
#dsh-nixon-hud .nh-parked{color:#e3b866}
#dsh-nixon-hud .nh-err{color:#e36f9a}
#dsh-nixon-hud .nh-flash{color:#7dd3a8;text-shadow:0 0 6px rgba(125,211,168,.7)}
#dsh-nixon-hud .nh-lo{color:#e36f9a;border:1px solid rgba(227,111,154,.5);
  border-radius:3px;padding:0 3px;margin-left:4px;font-size:9px}
#dsh-nixon-hud .nh-tag{grid-column:1 / 3;text-align:center;color:#5f726a;
  font-style:italic;margin-top:2px;letter-spacing:.05em}
#dsh-nixon-hud .nh-inv{display:none;grid-column:1/3;margin-top:4px;max-height:240px;overflow-y:auto;
  border-top:1px solid rgba(120,170,150,.2);padding-top:4px;font-size:10px;
  line-height:1.45;scrollbar-width:thin}
#dsh-nixon-hud .nh-inv .i{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  color:#8aa69a}
#dsh-nixon-hud .nh-inv .i.on{color:#7ad9a0}
#dsh-nixon-hud .nh-inv .i.off{color:#596b62;opacity:.55}
#dsh-nixon-hud .nh-inv .i.fail{color:#e36f9a}
#dsh-nixon-hud .nh-inv .i.warn{color:#e3b866}
#dsh-nixon-hud.nh-collapsed .nh-body{display:none}
#dsh-nixon-hud.nh-collapsed .nh-head .nh-chev{transform:rotate(-90deg)}
#dsh-nixon-hud.nh-inv-open .nh-inv{display:block}
#dsh-nixon-hud.nh-blink{border-color:rgba(125,211,168,.9);
  box-shadow:0 0 14px rgba(125,211,168,.45)}
`.trim();
				doc.head.appendChild(style);

				const root = doc.createElement("div");
				root.id = "dsh-nixon-hud";
				const boot = bootInfo();
				const entryCount = boot ? boot.entries.length : 0;

				let evtCell, bootCell, revCell, hmrCell, errCell, netCell, plugCell;
				const head = doc.createElement("div");
				head.className = "nh-head";
				head.title = "drag to move · click to collapse";
				head.innerHTML =
					'<span class="nh-chev">&#9660;</span><span>NIXON HUD</span>' +
					(loopback ? '<span class="nh-lo">LO</span>' : "");

				const body = doc.createElement("div");
				body.className = "nh-body";
				const row = (k, v) => {
					const a = doc.createElement("span");
					a.className = "k";
					a.textContent = k;
					const b = doc.createElement("span");
					b.className = "v";
					b.textContent = v;
					body.appendChild(a);
					body.appendChild(b);
					return b;
				};
				bootCell = row("BOOT", String(entryCount));
				revCell = row("REV", boot && boot.rev ? boot.rev : boot ? String(boot.entries[0] ? boot.entries[0].rev || "?" : "?") : "n/a");
				hmrCell = row("HMR", "0");
				errCell = row("ERR", "0");
				netCell = row("NET", "…");
				const hostRow = row("HOST", host || "?");
				evtCell = row("EVT", "…");
				const upCell = row("UP", "0:00");
				const clockCell = row("CLOCK", "--:--:--");
				plugCell = row("PLUGINS", "…");
				plugCell.className = "v click";
				plugCell.title = "toggle plugin inventory";

				const tag = doc.createElement("div");
				tag.className = "nh-tag";
				tag.textContent = TAGS[0];
				body.appendChild(tag);

				const inv = doc.createElement("div");
				inv.className = "nh-inv";

				root.appendChild(head);
				root.appendChild(body);
				body.appendChild(inv);
				doc.body.appendChild(root);

				// --- position restore + drag (persist to localStorage) ---
				const restorePos = () => {
					try {
						const s = localStorage.getItem(POS_KEY);
						if (!s) return;
						const p = JSON.parse(s);
						if (p && p.left) {
							root.style.right = "auto";
							root.style.bottom = "auto";
							root.style.left = p.left;
							root.style.top = p.top;
						}
					} catch (e) {}
				};
				const savePos = () => {
					try {
						localStorage.setItem(POS_KEY, JSON.stringify({
							left: root.style.left,
							top: root.style.top,
						}));
					} catch (e) {}
				};
				restorePos();

				let justDragged = false;
				head.addEventListener("click", () => {
					if (justDragged) {
						justDragged = false;
						return;
					}
					root.classList.toggle("nh-collapsed");
				});

				let drag = null;
				const onPointerDown = (ev) => {
					if (ev.button !== 0) return;
					const r = root.getBoundingClientRect();
					drag = {
						dx: ev.clientX - r.left,
						dy: ev.clientY - r.top,
						sx: ev.clientX,
						sy: ev.clientY,
						moved: false,
					};
				};
				const onPointerMove = (ev) => {
					if (!drag) return;
					if (!drag.moved && Math.abs(ev.clientX - drag.sx) + Math.abs(ev.clientY - drag.sy) < 4) return;
					drag.moved = true;
					root.style.right = "auto";
					root.style.bottom = "auto";
					root.style.left = ev.clientX - drag.dx + "px";
					root.style.top = ev.clientY - drag.dy + "px";
				};
				const onPointerUp = () => {
					if (!drag) return;
					justDragged = drag.moved;
					drag = null;
					if (justDragged) savePos();
				};
				head.addEventListener("pointerdown", onPointerDown);
				window.addEventListener("pointermove", onPointerMove);
				window.addEventListener("pointerup", onPointerUp);

				// --- plugin inventory from host /plugins/state ---
				const invOpen = () => root.classList.toggle("nh-inv-open");
				plugCell.addEventListener("click", invOpen);
				const renderInv = () => {
					if (!state || !state.entries) return;
					let on = 0;
					inv.textContent = "";
					for (const e of state.entries) {
						if (e.enabled) on++;
						const line = doc.createElement("div");
						let cls = "i " + (e.enabled ? "on" : "off");
						if (e.phase === "failed") cls = "i fail";
						else if (e.phase === "loading" || e.phase === "pending") cls = "i warn";
						line.className = cls;
						line.textContent =
							(e.enabled ? "● " : "○ ") + e.id +
							(e.phase && e.phase !== "active" ? " · " + e.phase : "");
						line.title = e.name || e.id;
						inv.appendChild(line);
					}
					plugCell.textContent = on + "/" + state.entries.length;
				};
				let state = null;
				const refreshState = () => {
					try {
						fetch("/plugins/state", { cache: "no-store" })
							.then((r) => (r.ok ? r.json() : null))
							.then((j) => {
								if (j && j.entries) {
									state = j;
									renderInv();
								}
							})
							.catch(() => {});
					} catch (e) {}
				};
				refreshState();

				// --- NET / online state ---
				const updateNet = () => {
					const c = navigator.connection;
					if (navigator.onLine === false) {
						netCell.textContent = "offline";
						netCell.className = "v nh-parked";
						return;
					}
					if (c && typeof c.downlink === "number") {
						const dl = c.downlink >= 10 ? Math.round(c.downlink) + "M" : c.downlink.toFixed(1) + "M";
						netCell.textContent =
							dl +
							(typeof c.rtt === "number" ? " · " + Math.round(c.rtt) + "ms" : "") +
							(c.effectiveType ? " · " + c.effectiveType : "");
					} else {
						netCell.textContent = "online";
					}
					netCell.className = "v";
				};
				updateNet();
				window.addEventListener("online", updateNet);
				window.addEventListener("offline", updateNet);

				// --- stealth error counter ---
				let errCount = 0;
				const onErr = () => {
					errCount++;
					errCell.textContent = String(errCount);
					errCell.className = "v nh-err";
				};
				window.addEventListener("error", onErr);
				window.addEventListener("unhandledrejection", onErr);

				const started = Date.now();
				let prev = new Map();
				let rebuilds = 0;

				const blink = () => {
					root.classList.add("nh-blink");
					setTimeout(() => {
						try {
							root.classList.remove("nh-blink");
						} catch (e) {}
					}, 700);
				};

				const flashCell = (cell, text) => {
					if (!cell) return;
					cell.textContent = text;
					cell.className = "v nh-flash";
					setTimeout(() => {
						try {
							if (cell.textContent === text) cell.className = "v";
						} catch (e) {}
					}, 1200);
				};

				// live graph frame from SSE -> live rev/entry count + delta
				const onGraph = (g) => {
					try {
						const entries = (g && g.entries) || [];
						const rev = (g && g.rev) || "?";
						if (bootCell) bootCell.textContent = String(entries.length);
						if (revCell) revCell.textContent = rev;
						if (!prev.size) {
							prev = new Map(entries.map((e) => [e.id, e.rev]));
							return;
						}
						let changed = 0;
						const seen = new Set();
						for (const e of entries) {
							seen.add(e.id);
							if (prev.get(e.id) !== e.rev) changed++;
						}
						for (const id of prev.keys()) if (!seen.has(id)) changed++;
						prev = new Map(entries.map((e) => [e.id, e.rev]));
						if (changed > 0) {
							flashCell(hmrCell, "\u0394" + changed);
							blink();
							refreshState();
						}
					} catch (e) {}
				};

				// clock tick and tagline rotation
				let tickCount = 0;
				const clockTimer = setInterval(() => {
					try {
						const d = new Date();
						clockCell.textContent =
							String(d.getHours()).padStart(2, "0") +
							":" +
							String(d.getMinutes()).padStart(2, "0") +
							":" +
							String(d.getSeconds()).padStart(2, "0");
						upCell.textContent = fmt(Date.now() - started);
						if (++tickCount % 7 === 0) {
							tag.textContent = TAGS[Math.floor(Math.random() * TAGS.length)];
						}
					} catch (e) {}
				}, 1000);

				// SSE liveness probe + graph/rebuilt tracking — best-effort.
				let source = null;
				try {
					source = new EventSource("/plugins/events");
					source.onopen = () => {
						evtCell.textContent = "LIVE";
						evtCell.className = "v nh-live";
					};
					source.onerror = () => {
						evtCell.textContent = "PARKED";
						evtCell.className = "v nh-parked";
					};
					source.onmessage = (msg) => {
						evtCell.textContent = "LIVE";
						evtCell.className = "v nh-live";
						try {
							const data = JSON.parse(msg.data);
							if (data && data.type === "graph") onGraph(data.graph);
							else if (data && data.type === "rebuilt") {
								rebuilds++;
								if (hmrCell) hmrCell.textContent = String(rebuilds);
								flashCell(hmrCell, "HMR#" + rebuilds);
								blink();
							}
						} catch (e) {}
					};
					setTimeout(() => {
						if (source && source.readyState === 0) {
							evtCell.textContent = "PARKED";
							evtCell.className = "v nh-parked";
						}
					}, 4000);
				} catch (e) {
					evtCell.textContent = "PARKED";
					evtCell.className = "v nh-parked";
				}

				const cleanup = () => {
					try {
						if (source) source.close();
					} catch (e) {}
					try {
						clearInterval(clockTimer);
					} catch (e) {}
					window.removeEventListener("pointermove", onPointerMove);
					window.removeEventListener("pointerup", onPointerUp);
					window.removeEventListener("online", updateNet);
					window.removeEventListener("offline", updateNet);
					window.removeEventListener("error", onErr);
					window.removeEventListener("unhandledrejection", onErr);
					try {
						if (root && root.parentNode) root.parentNode.removeChild(root);
					} catch (e) {}
					try {
						if (style && style.parentNode) style.parentNode.removeChild(style);
					} catch (e) {}
				};

				// prefer the DSH effect registry when available; else pagehide.
				if (ctx && typeof ctx.effect === "function") {
					ctx.effect(cleanup, "nixon-hud");
				} else {
					window.addEventListener("pagehide", cleanup);
				}
			} catch (e) {
				/* die silently — no console spam */
			}
		}

		exports.apply = apply;
		exports.inject = [];
		exports.name = "nixon-hud";
		return module.exports;
	},
});
