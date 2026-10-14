/**
 * Navigation interaction test.
 *
 * The layout audit proves geometry; it cannot prove that a chip does
 * anything. A chip whose id does not match the render switch renders
 * nothing at all — no error, no warning, just a blank page — and no amount
 * of measuring will find it. This clicks every main tab and every chip on
 * every tool and asserts the main region actually changed.
 *
 * Order matters. The chip row belongs to the WORKING surface, so it does not
 * exist while the Overview is open. The chips are therefore collected after
 * the main-tab pass has put the working surface on screen, and the test
 * finishes by asserting the Overview hides them again.
 *
 *   node navtest.mjs
 */

import puppeteer from "puppeteer-core";

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const BASE = "http://127.0.0.1:7000";

const TOOLS = [
  ["#/t/malware", "Malware Analyzer"],
  ["#/t/ioc", "IOC Lookup"],
  ["#/t/events", "Event Analyzer"],
  ["#/t/phishing", "Phishing Detector"],
  ["#/t/ruleforge", "RuleForge"],
];

/* Tools whose surfaces need data before their chips can differ. Malware
   Analyzer's chips select sections OF a report, so with no report loaded
   every chip correctly shows the same scan list and the test would call
   that a failure. Seed the data first, then test the real path.
   The labels are the tools' own landing-page CTAs. */
const SEED = {
  "Malware Analyzer": "Past Scans",
  "Phishing Detector": "Past Scans",
};

const MAIN_TABS = 'header [role=tab]:not([data-chip])';
const CHIPS = "header [data-chip]";

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

let failures = 0;
let checks = 0;

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

for (const [hash, name] of TOOLS) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1000 });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e.message)));
  await page.evaluateOnNewDocument(() =>
    localStorage.setItem(
      "secconflux.visits",
      JSON.stringify({ home: 9, malware: 9, ioc: 9, events: 9, phishing: 9, ruleforge: 9 }),
    ),
  );
  await page.goto(`${BASE}/${hash}`, { waitUntil: "domcontentloaded" });
  await pause(700);

  if (SEED[name]) {
    const seeded = await page.evaluate((label) => {
      const b = [...document.querySelectorAll("main button")].find((x) =>
        x.textContent.includes(label),
      );
      if (!b) return false;
      b.click();
      return true;
    }, SEED[name]);
    await pause(450);
    console.log(`  seeded   ${SEED[name]} ${seeded ? "ok" : "NOT FOUND"}`);
  }

  // Fingerprint the main region so a change is detectable.
  const fingerprint = () =>
    page.evaluate(() => {
      const m = document.querySelector("main");
      return {
        text: (m?.innerText ?? "").replace(/\s+/g, " ").trim().slice(0, 400),
        children: m?.querySelectorAll("div").length ?? 0,
      };
    });

  const list = (sel) =>
    page.evaluate((s) => {
      return [...document.querySelectorAll(s)].map((el, i) => ({
        i,
        label: el.textContent.trim(),
        active: el.getAttribute("aria-selected") === "true",
      }));
    }, sel);

  const clickIndex = (sel, i) =>
    page.evaluate(
      (s, idx) => {
        const el = [...document.querySelectorAll(s)][idx];
        if (!el) return false;
        el.click();
        return true;
      },
      sel,
      i,
    );

  const clickAll = async (sel, items) => {
    for (const c of items) {
      /* Clicking the control that is already selected is a no-op by design,
         and asserting on it would report the starting state as a failure. */
      if (c.active) {
        console.log(`  skip     ${c.label.padEnd(16)} already selected`);
        continue;
      }
      const before = await fingerprint();
      const ok = await clickIndex(sel, c.i);
      await pause(320);
      const after = await fingerprint();
      checks++;
      if (!ok) {
        console.log(`  MISSING  ${c.label}`);
        failures++;
      } else if (after.text === before.text && after.children === before.children) {
        console.log(`  NO-OP    ${c.label.padEnd(16)} main region did not change`);
        failures++;
      } else {
        console.log(`  ok       ${c.label}`);
      }
    }
  };

  const mainTabs = await list(MAIN_TABS);
  console.log(`\n${name}  (${mainTabs.length} main tabs)`);

  await clickAll(MAIN_TABS, mainTabs);

  // Put the working surface on screen before looking for its chips.
  await page.evaluate((s) => {
    [...document.querySelectorAll(s)][1]?.click();
  }, MAIN_TABS);
  await pause(420);

  const chips = await list(CHIPS);
  console.log(`  chips on the working surface: ${chips.length}`);
  await clickAll(CHIPS, chips);

  /* The Overview must not offer the working surface's sections. A chip row
     under a page that describes the tool offers six sections of a screen
     that is not on display. */
  await page.evaluate((s) => {
    [...document.querySelectorAll(s)][0]?.click();
  }, MAIN_TABS);
  await pause(380);
  const leaked = await page.evaluate((s) => document.querySelectorAll(s).length, CHIPS);
  checks++;
  if (leaked > 0) {
    console.log(`  LEAK     ${leaked} chips still visible on the Overview`);
    failures++;
  } else {
    console.log(`  ok       Overview hides the section chips`);
  }

  if (errors.length) {
    console.log(`  RUNTIME ERRORS: ${[...new Set(errors)].join(" | ")}`);
    failures++;
  }
  await page.close();
}

await browser.close();
console.log(`\n${checks} navigation checks, ${failures} failures`);
process.exit(failures ? 1 : 0);
