/**
 * Screenshots.
 *
 * The audit proves the geometry. This is for the things geometry cannot
 * judge: whether a page looks composed, whether the accent is the right one,
 * whether a card grid reads as even. Everything here is captured from the
 * real build at real viewports.
 *
 *   node shots.mjs
 */

import puppeteer from "puppeteer-core";
import { mkdirSync } from "node:fs";

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const BASE = "http://127.0.0.1:7000";
const OUT = "shots";

mkdirSync(OUT, { recursive: true });

const PAGES = [
  ["#/", "home"],
  ["#/t/malware", "malware"],
  ["#/t/ioc", "ioc"],
  ["#/t/events", "events"],
  ["#/t/phishing", "phishing"],
  ["#/t/ruleforge", "ruleforge"],
];

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage", "--force-color-profile=srgb"],
});

async function shoot(hash, name, theme, width, tag) {
  const page = await browser.newPage();
  await page.setViewport({ width, height: 950, deviceScaleFactor: 1 });
  await page.evaluateOnNewDocument((t) => {
    localStorage.setItem("secconflux.theme", t);
    localStorage.setItem(
      "secconflux.visits",
      JSON.stringify({
        home: 9, malware: 9, ioc: 9, events: 9, phishing: 9, ruleforge: 9,
      }),
    );
  }, theme);
  await page.goto(`${BASE}/${hash}`, { waitUntil: "domcontentloaded" });
  await new Promise((r) => setTimeout(r, 800));
  const file = `${OUT}/${name}-${tag}.png`;
  await page.screenshot({ path: file });
  await page.close();
  console.log(`  ${file}`);
}

console.log("dark 1920:");
for (const [h, n] of PAGES) await shoot(h, n, "dark", 1920, "dark");
console.log("light 1920:");
for (const [h, n] of PAGES) await shoot(h, n, "light", 1920, "light");
console.log("dark 1280:");
for (const [h, n] of PAGES) await shoot(h, n, "dark", 1280, "1280");

await browser.close();
console.log("done");
