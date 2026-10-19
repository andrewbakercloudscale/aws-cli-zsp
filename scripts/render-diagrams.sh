#!/usr/bin/env bash
# Renders docs/diagrams/diagrams.html to docs/images/diagram-<id>.png, one per <section>.
# Needs Node and Playwright: PLAYWRIGHT_DIR=/path/to/node_modules/playwright, or a
# `playwright` that Node can require from here.
set -euo pipefail
cd "$(dirname "$0")/.."
PW="${PLAYWRIGHT_DIR:-playwright}"
node - "$PW" "$PWD/docs/diagrams/diagrams.html" "$PWD/docs/images" <<'JS'
const [pw, page, out] = process.argv.slice(2);
const { chromium } = require(pw);
(async () => {
  const browser = await chromium.launch();
  const p = await browser.newPage({ deviceScaleFactor: 2, viewport: { width: 800, height: 1000 } });
  await p.goto('file://' + page);
  for (const s of await p.$$('section.diagram')) {
    const id = await s.getAttribute('id');
    await s.screenshot({ path: `${out}/diagram-${id}.png`, omitBackground: true });
    console.log(`docs/images/diagram-${id}.png`);
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
JS
