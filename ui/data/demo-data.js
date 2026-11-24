/* Clearly illustrative mini-shop scan data. Replace with a Stage 3 report bundle. */
window.demoData = {
  repo: { name: "mini-shop", language: "Python", branch: "main", commit: "a91c4e2", scannedAt: "Nov 23, 2026 · 14:32", summary: "A small Flask checkout service. Public checkout requests reach Stripe payment processing and persist orders; checkout also sends an event to an external collection endpoint.", files: 18, functions: 24, routes: 1, packages: 7, modules: 5, commitLabel: "a91c4e2" },
  coverage: { files: { parsed: 17, total: 18 }, calls: { resolved: 14, total: 15 }, modules: { carded: 5, total: 5 }, filesCarded: { carded: 4, total: 18 }, questions: { resolved: 3, total: 4 }, knownUnknowns: ["1 dynamic import in app/plugins.py:12", "app/legacy.py could not be parsed (syntax error)"] },
  modules: [
    { id: "module:api", name: "api", path: "app/api", files: 3, functions: 5, purpose: "Accepts checkout requests and routes them to payment and event handling.", tags: ["entry point", "user input"], evidence: "app/api/routes.py:8–16", confidence: 0.96, x: 155, y: 118, color: "blue" },
    { id: "module:payments", name: "payments", path: "app/payments", files: 4, functions: 7, purpose: "Creates Stripe charges and records completed orders.", tags: ["secret access", "database write", "external service"], evidence: "app/payments/service.py:5–18", confidence: 0.94, x: 360, y: 72, color: "violet" },
    { id: "module:models", name: "models", path: "app/models.py", files: 1, functions: 2, purpose: "Defines the Order model and orders table mapping.", tags: ["database"], evidence: "app/models.py:4–12", confidence: 0.99, x: 360, y: 195, color: "teal" },
    { id: "module:utils", name: "utils", path: "app/utils", files: 2, functions: 3, purpose: "Sends checkout events to an external collection endpoint.", tags: ["network", "recently changed"], evidence: "app/utils/helpers.py:4–9", confidence: 0.91, x: 566, y: 118, color: "amber" },
    { id: "module:tests", name: "tests", path: "tests", files: 3, functions: 7, purpose: "Exercises API and payment behavior.", tags: ["test code"], evidence: "tests/test_api.py:1–28", confidence: 0.98, x: 155, y: 225, color: "gray" }
  ],
  edges: [{ from: "api", to: "payments", weight: 3 }, { from: "api", to: "utils", weight: 1 }, { from: "payments", to: "models", weight: 2 }, { from: "tests", to: "api", weight: 1 }],
  paths: [
    { entry: "POST /checkout", input: "request.json", handler: "checkout()", steps: ["checkout()", "charge()", "get_client()"], sinks: ["Stripe API", "orders table", "STRIPE_KEY"], evidence: ["app/api/routes.py:10", "app/payments/service.py:8", "app/payments/client.py:11"], confidence: 0.96, kind: "payment" },
    { entry: "POST /checkout", input: "request.json", handler: "checkout()", steps: ["checkout()", "send_event()"], sinks: ["https://events.example.net/collect"], evidence: ["app/api/routes.py:14", "app/utils/helpers.py:6"], confidence: 0.91, kind: "network" }
  ],
  packages: [
    { name: "stripe", version: "7.0.0", direct: true, used: true, radius: "large", files: 1, functions: ["charge()"], routes: ["POST /checkout"], nearby: ["STRIPE_KEY", "orders table"], apiCalls: ["stripe.Charge.create"], reasons: ["Reachable from a public route", "Same path reads a secret and writes to the database"], evidence: "app/payments/client.py:1,11", confidence: 1.0 },
    { name: "PyYAML", version: "6.0.1", direct: true, used: true, radius: "internal", files: 1, functions: ["load_config()"], routes: [], nearby: [], apiCalls: ["yaml.load"], reasons: ["Used by internal configuration loading"], evidence: "app/config/load.py:7", confidence: 1.0 },
    { name: "requests", version: "2.32.3", direct: true, used: true, radius: "public", files: 1, functions: ["send_event()"], routes: ["POST /checkout"], nearby: ["external service"], apiCalls: ["requests.post"], reasons: ["Network call reachable from a public route"], evidence: "app/utils/helpers.py:6", confidence: 1.0 },
    { name: "Flask", version: "3.0.3", direct: true, used: true, radius: "public", files: 1, functions: ["checkout()"], routes: ["POST /checkout"], nearby: [], apiCalls: ["Flask route"], reasons: ["Defines the public application route"], evidence: "app/api/routes.py:8", confidence: 1.0 },
    { name: "SQLAlchemy", version: "2.0.32", direct: true, used: true, radius: "large", files: 2, functions: ["charge()"], routes: ["POST /checkout"], nearby: ["orders table"], apiCalls: ["session.add", "session.commit"], reasons: ["Public checkout writes order data"], evidence: "app/payments/service.py:15", confidence: 1.0 },
    { name: "colorama", version: "0.4.6", direct: true, used: false, radius: "none", files: 0, functions: [], routes: [], nearby: [], apiCalls: [], reasons: ["Declared in requirements.txt with no matching import found"], evidence: "requirements.txt:6", confidence: 0.99 }
  ],
  changes: [
    { date: "Nov 23", commit: "a91c4e2", title: "Add checkout event reporting", detail: "Introduced the utils module and a network call from checkout.", type: "notable", items: ["+ app/utils/helpers.py", "+ CONTACTS → events.example.net", "+ colorama 0.4.6"] },
    { date: "Nov 22", commit: "c28bf10", title: "Update YAML parser", detail: "Bumped PyYAML to address compatibility with the runtime.", type: "dependency", items: ["PyYAML 5.4.1 → 6.0.1"] },
    { date: "Nov 18", commit: "8d991a0", title: "Initial checkout implementation", detail: "Added Flask route, Stripe client, and Order persistence.", type: "baseline", items: ["+ POST /checkout", "+ stripe 7.0.0", "+ orders table"] }
  ],
  findings: [
    { title: "New outbound event call from checkout", severity: "notable", status: "resolved", text: "send_event() posts checkout event data to an external domain. The helper and call site both appeared in the latest commit.", evidence: ["app/utils/helpers.py:4–9", "app/api/routes.py:14", "commit:a91c4e2"], confidence: 0.91, category: "Network change", steps: 4 },
    { title: "colorama is declared but unused", severity: "info", status: "resolved", text: "The direct dependency appears in requirements.txt, but no runtime or test import was found.", evidence: ["requirements.txt:6"], confidence: 0.99, category: "Dependency question", steps: 2 },
    { title: "Dynamic import could not be resolved", severity: "review", status: "unresolved", text: "A dynamic import prevents static confirmation of the loaded module and its package ownership.", evidence: ["app/plugins.py:12"], confidence: 0.72, category: "Known unknown", steps: 1 }
  ]
};
