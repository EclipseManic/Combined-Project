/** Proves the background does not scroll behind an open overlay.
 *
 *  Each case reloads first. Reusing one page let state leak between cases —
 *  an Escape that closed the dropdown followed by a click that reopened it —
 *  so a case could be measured with the wrong overlay on screen and report a
 *  leak that was not there. A reload per case costs a second and removes the
 *  whole class of error.
 *
 *   node scrolltest.mjs
 */
import puppeteer from "puppeteer-core";

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox"],
});

const page = await browser.newPage();
await page.setViewport({ width: 1600, height: 700 });
await page.evaluateOnNewDocument(() =>
  localStorage.setItem(
    "secconflux.visits",
    JSON.stringify({ home: 9, malware: 9, ioc: 9, events: 9, phishing: 9, ruleforge: 9 }),
  ),
);

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const HASH = "#/t/events";

async function load() {
  await page.goto(`http://127.0.0.1:7000/${HASH}`, { waitUntil: "domcontentloaded" });
  await pause(800);
  await page.evaluate(() => window.scrollTo(0, 500));
  await pause(250);
}

/** Wheel at an explicit point.
 *
 *  The point matters and must not be hard-coded. A wheel at a fixed
 *  coordinate reads as "the page scrolled" for the dropdown case even when
 *  the dropdown is holding perfectly — because the pointer was never over
 *  the dropdown to begin with. */
async function wheelAndMeasure(at) {
  await page.mouse.move(at.x, at.y);
  await pause(150);
  const before = await page.evaluate(() => window.scrollY);
  await page.mouse.wheel({ deltaY: 900 });
  await pause(500);
  const after = await page.evaluate(() => window.scrollY);
  return { before, after, moved: Math.abs(after - before) > 5 };
}

const cases = [
  {
    label: "no overlay (control)",
    open: async () => {},
    shouldScroll: true,
  },
  {
    label: "brand switcher dropdown",
    open: async () => {
      await page.evaluate(() => {
        document.querySelector('[aria-label="SecConflux — switch tool"]')?.click();
      });
      await pause(450);
    },
    hover: '[role=listbox]',
    shouldScroll: false,
  },
  {
    label: "command palette (Ctrl+M)",
    open: async () => {
      await page.keyboard.down("Control");
      await page.keyboard.press("m");
      await page.keyboard.up("Control");
      await pause(500);
    },
    shouldScroll: false,
  },
  {
    label: "tour (?)",
    open: async () => {
      await page.keyboard.press("?");
      await pause(500);
    },
    shouldScroll: false,
  },
  {
    label: "modal (event detail)",
    open: async () => {
      await page.evaluate(() => {
        const row = [...document.querySelectorAll("main tbody tr")][0];
        if (row instanceof HTMLElement) row.click();
      });
      await pause(500);
    },
    shouldScroll: false,
  },
];

let bad = 0;
for (const c of cases) {
  await load();
  await c.open();
  // Default wheel point is the middle of the viewport, which is over the
  // page for a full-screen overlay. For a dropdown it must be over the
  // dropdown, so the case supplies its own point.
  const at =
    (c.hover &&
      (await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) return null;
        const b = el.getBoundingClientRect();
        return { x: b.left + b.width / 2, y: b.top + Math.min(b.height / 2, 40) };
      }, c.hover))) || { x: 800, y: 300 };

  const r = await wheelAndMeasure(at);
  const ok = c.shouldScroll ? r.moved : !r.moved;
  if (!ok) bad++;
  console.log(
    `${c.label.padEnd(28)} scrollY ${r.before} -> ${r.after}  ` +
      `${r.moved ? "moved" : "held"}  ${ok ? "ok" : "WRONG"}`,
  );
}

console.log(bad === 0 ? "\nPASS" : `\nFAIL — ${bad} case(s) wrong`);
await browser.close();
process.exit(bad ? 1 : 0);