/**
 * Layout audit.
 *
 * Measures the live DOM in a real browser and reports only things that are
 * measurably wrong: controls of differing heights sharing a row, elements
 * overflowing their parent, off-centre navigation, duplicate ids, text that
 * clips. Guessing at alignment from the CSS is how it went wrong the first
 * time; this reads the rendered result.
 *
 *   node audit.mjs
 */

import puppeteer from "puppeteer-core";

const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const BASE = "http://127.0.0.1:7000";

const ROUTES = [
  ["#/", "home"],
  ["#/t/malware", "malware"],
  ["#/t/ioc", "ioc"],
  ["#/t/events", "events"],
  ["#/t/phishing", "phishing"],
  ["#/t/ruleforge", "ruleforge"],
];

/** The widths that break layouts are the narrow ones, and the theme that
 *  breaks contrast is the other one. Checking a single 1600px dark viewport
 *  is how a row of chips ends up 28px next to a 34px button unnoticed. */
const VIEWPORTS = [
  [1920, 1080, "1920"],
  [1440, 900, "1440"],
  [1280, 800, "1280"],
  [1024, 768, "1024"],
  [768, 900, "768"],
];
const THEMES = ["dark", "light"];

/** Runs in the page. Collects every measurable defect in one pass. */
function collect() {
  const problems = [];
  const note = (kind, detail, node) =>
    problems.push({
      kind,
      detail,
      tag: node?.tagName ?? "",
      cls: (node?.className?.baseVal ?? node?.className ?? "")
        .toString()
        .slice(0, 90),
      parent: (node?.parentElement?.className ?? "")
        .toString()
        .slice(0, 70),
    });

  const px = (el, p) => parseFloat(getComputedStyle(el)[p]) || 0;
  /* Hidden elements measure 0 and would otherwise be reported as "a control
     of height 0 next to a control of height 32". A responsive element that is
     deliberately hidden at this breakpoint is not a defect. */
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };

  /* ---- 1. duplicate ids ------------------------------------------ */
  const seen = new Map();
  for (const el of document.querySelectorAll("[id]")) {
    seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
  }
  for (const [id, n] of seen) if (n > 1) note("duplicate-id", `${id} x${n}`);

  /* ---- 2. horizontal page overflow -------------------------------- */
  if (document.documentElement.scrollWidth > window.innerWidth + 1) {
    note(
      "page-overflow-x",
      `scrollWidth ${document.documentElement.scrollWidth} > viewport ${window.innerWidth}`,
    );
  }

  /* ---- 3. controls of mixed height inside one row ------------------
     Only interactive elements are compared. Comparing an icon against a
     button reports a difference that is correct by design and buries the
     real ones; the question worth asking is whether two THINGS YOU CAN
     CLICK in the same row are the same size. */
  const CLICKABLE = "button, a[href], input, select, [role=tab], [role=button]";
  const rows = new Set();
  for (const el of document.querySelectorAll(CLICKABLE)) {
    const p = el.parentElement;
    if (p) rows.add(p);
  }
  for (const row of rows) {
    const kids = [...row.querySelectorAll(":scope > " + CLICKABLE)].filter((k) => {
      const r = k.getBoundingClientRect();
      const s = getComputedStyle(k);
      return r.height > 0 && r.width > 8 && s.display !== "none" && s.visibility !== "hidden";
    });
    if (kids.length < 2) continue;
    const hs = kids.map((k) => Math.round(k.getBoundingClientRect().height));
    const lo = Math.min(...hs);
    const hi = Math.max(...hs);
    if (hi - lo >= 4) {
      note(
        "mixed-control-height",
        `${hs.join("/")} spread ${hi - lo}px in a row of clickable siblings`,
        kids[hs.indexOf(hi)],
      );
    }
    /* Baseline alignment: siblings of different heights in one row are
       centred against each other, which reads as uneven text when the
       difference is small. Flag it when the offset is visible. */
    const tops = kids.map((k) => Math.round(k.getBoundingClientRect().top));
    if (hi - lo >= 6 && Math.max(...tops) - Math.min(...tops) >= 4) {
      note(
        "uneven-baseline",
        `tops ${tops.join("/")} differ by ${Math.max(...tops) - Math.min(...tops)}px`,
      );
    }
  }

  /* ---- 4. badges / chips of mixed height in one wrap row ------------ */
  for (const row of document.querySelectorAll(".flex.flex-wrap")) {
    const badges = [...row.children].filter((k) => {
      const s = getComputedStyle(k);
      return (
        s.display === "inline-flex" &&
        px(k, "height") > 0 &&
        k.childElementCount === 0
      );
    });
    if (badges.length < 2) continue;
    const hs = badges.map((k) => Math.round(k.getBoundingClientRect().height));
    if (Math.max(...hs) - Math.min(...hs) >= 3) {
      note("mixed-badge-height", `heights ${hs.join("/")} in a wrap row`);
    }
  }

  /* ---- 5. elements overflowing their parent horizontally ----------- */
  for (const el of document.querySelectorAll("main *")) {
    const p = el.parentElement;
    if (!p) continue;
    const cs = getComputedStyle(el);
    if (cs.overflowX === "auto" || cs.overflowX === "scroll") continue;
    if (cs.position === "absolute" || cs.position === "fixed") continue;
    const e = el.getBoundingClientRect();
    const q = p.getBoundingClientRect();
    if (e.width === 0 || q.width === 0) continue;
    if (e.right > q.right + 2 && getComputedStyle(p).overflowX === "visible") {
      note(
        "overflow-parent",
        `${el.tagName}.${el.className.toString().slice(0, 40)} exceeds parent by ${Math.round(
          e.right - q.right,
        )}px`,
        el,
      );
    }
  }

  /* ---- 6. the centre nav is actually centred -----------------------
     The header is a three-track grid: brand, centre, right. The two 1fr
     side tracks are SUPPOSED to sit off-centre, so only the middle track is
     checked. Flagging all three measured the layout working correctly. */
  const header = document.querySelector("header");
  if (header) {
    const grid = header.firstElementChild;
    if (grid && getComputedStyle(grid).display === "grid") {
      const gr = grid.getBoundingClientRect();
      const mid = gr.left + gr.width / 2;
      const centre = grid.children[1];
      if (centre) {
        const c = centre.getBoundingClientRect();
        const drift = Math.round(c.left + c.width / 2 - mid);
        if (Math.abs(drift) > 1) {
          note(
            "centre-track-drift",
            `centre track is ${drift}px off the viewport centre`,
            centre,
          );
        }
      }
      // The side tracks must be equal, or the centre is biased even if it
      // happens to look centred relative to its own box.
      const l = grid.children[0]?.getBoundingClientRect().width ?? 0;
      const r = grid.children[2]?.getBoundingClientRect().width ?? 0;
      if (Math.abs(l - r) >= 1) {
        note("uneven-side-tracks", `left ${l.toFixed(0)}px vs right ${r.toFixed(0)}px`);
      }
    }
    const tabs = [...header.querySelectorAll('[role="tab"]')].filter(visible);
    if (tabs.length) {
      const hs = tabs.map((c) => Math.round(c.getBoundingClientRect().height));
      if (Math.max(...hs) - Math.min(...hs) >= 3) {
        note("header-tab-height-mix", `tab heights ${hs.join("/")}`);
      }
    }
    /* The RIGHT RAIL specifically, marked with data-rail. Walking up from a
       tab to measure "the rail" lands on the CENTRE group instead, which is
       how a 22px status chip next to a 32px theme toggle went unreported. */
    const rail = header.querySelector("[data-rail]");
    if (rail) {
      const ctrls = [...rail.querySelectorAll(CLICKABLE)].filter(visible);
      const hs2 = ctrls.map((k) => Math.round(k.getBoundingClientRect().height));
      if (hs2.length > 1 && Math.max(...hs2) - Math.min(...hs2) >= 3) {
        note("header-rail-height-mix", `right rail ${hs2.join("/")}`);
      }
    }
  }

  /* ---- 6b. stat values share a baseline -----------------------------
     A label that wraps to two lines pushes its value down, so a row of four
     tiles ends up with four numbers on four different baselines. Marked with
     data-tile: guessing "is this a StatTile" from a class name matched
     unrelated grids and reported a 116px spread that does not exist. */
  {
    for (const parent of document.querySelectorAll("main [data-tile]")) {
      const grid = parent.parentElement;
      if (!grid) continue;
      const tiles = [...grid.children].filter((c) => c.hasAttribute("data-tile"));
      if (tiles.length < 2) continue;
      /* Group by ROW first. A 2x2 grid holds two rows of tiles, and the
         second row's values are naturally ~100px lower; comparing the whole
         grid reported a 116px "drift" that is just the grid working. */
      const rows = new Map();
      for (const t of tiles) {
        const key = Math.round(t.getBoundingClientRect().top);
        if (!rows.has(key)) rows.set(key, []);
        rows.get(key).push(t);
      }
      for (const [, row] of rows) {
        if (row.length < 2) continue;
        const tops = row.map((t) => {
          const v = t.querySelector("[data-tile-value]");
          return v ? Math.round(v.getBoundingClientRect().top) : null;
        });
        if (tops.some((t) => t === null)) continue;
        const spread = Math.max(...tops) - Math.min(...tops);
        if (spread >= 3) {
          note(
            "stat-baseline-drift",
            `values start ${spread}px apart in one row of ${row.length}`,
          );
        }
      }
    }
  }

  /* ---- 7. text that clips its own box ------------------------------ */
  for (const el of document.querySelectorAll("main span, main div, main button")) {
    if (el.children.length) continue;
    const s = getComputedStyle(el);
    if (s.overflow === "visible") continue;
    if (s.webkitLineClamp && s.webkitLineClamp !== "none") continue;
    if (el.scrollWidth > el.clientWidth + 2 && s.textOverflow !== "ellipsis") {
      note(
        "clipped-text",
        `scrollW ${el.scrollWidth} > clientW ${el.clientWidth} with no ellipsis`,
        el,
      );
    }
    if (el.scrollHeight > el.clientHeight + 2 && s.overflowY !== "auto") {
      note(
        "clipped-vertical",
        `scrollH ${el.scrollHeight} > clientH ${el.clientHeight}`,
        el,
      );
    }
  }

  /* ---- 8. every interactive control is big enough to hit ---------- */
  for (const el of document.querySelectorAll("header button")) {
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.height > 0 && r.height < 24) {
      note("small-hit-target", `height ${Math.round(r.height)}px in header`, el);
    }
  }

  /* ---- 9. every main nav destination is reachable at this width ----
     A control hidden by a breakpoint is correct; a whole NAVIGATION hidden
     by a breakpoint is a dead end. Only `data-chip` elements are section
     chips: the Home page renders its five tools as tabs too, and counting
     those as chips reports a dead end that does not exist. */
  {
    const chips = [...document.querySelectorAll("header [data-chip]")];
    if (chips.length) {
      const anyVisible = chips.some(visible);
      const anyReachable = !!document.querySelector("header [data-sections-menu]");
      if (!anyVisible && !anyReachable) {
        note(
          "unreachable-nav",
          `${chips.length} section chips are all hidden with no fallback control`,
        );
      }
    }
  }

  /* ---- 10. siblings overlapping each other --------------------------
     The header's right rail puts a scrolling chip row next to a fixed action
     button. If the chip row cannot shrink, the two draw on top of each
     other and the last chip becomes unclickable. Parent/child overflow does
     not catch this; only a sibling box test does. */
  {
    const groups = [
      ["header", "header rail"],
      ["main .flex.items-center.gap-3", "action row"],
      ["main .flex.items-center.gap-2", "chip row"],
    ];
    for (const [sel, label] of groups) {
      for (const g of document.querySelectorAll(sel)) {
        const kids = [...g.children].filter(visible);
        for (let i = 0; i < kids.length; i++) {
          for (let j = i + 1; j < kids.length; j++) {
            const a = kids[i].getBoundingClientRect();
            const b = kids[j].getBoundingClientRect();
            const ox = Math.min(a.right, b.right) - Math.max(a.left, b.left);
            const oy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
            // Overlap on both axes, by more than a rounding error.
            if (ox > 2 && oy > 2) {
              note(
                "sibling-overlap",
                `${label}: two controls overlap by ${Math.round(ox)}x${Math.round(oy)}px`,
                kids[j],
              );
            }
          }
        }
      }
    }
  }

  /* ---- 11. a bar chart whose bars are zero-height ------------------
     `height: 40%` inside a parent with `height: auto` resolves to 0. A
     percentage height needs a definite ancestor, and when it is missing the
     chart renders as an empty box with axis labels and nothing between
     them, which reads as "no data" rather than "broken". */
  {
    for (const el of document.querySelectorAll("main *")) {
      // The DECLARED value, not the computed one: getComputedStyle resolves a
      // percentage against the parent and hands back used pixels, so "60%"
      // arrives as "0px" and a naive endsWith("%") test never fires.
      const declared = el.style.height;
      if (!declared || !declared.endsWith("%")) continue;
      const r = el.getBoundingClientRect();
      if (r.height > 0.5) continue;
      const p = el.parentElement;
      if (!p) continue;
      const ph = p.getBoundingClientRect().height;
      note(
        "zero-height-percentage",
        `height:${declared} collapsed to 0 inside a ${Math.round(ph)}px parent`,
        el,
      );
    }
  }

  return {
    problems,
    stats: {
      buttons: document.querySelectorAll("button").length,
      cards: document.querySelectorAll('[class*="rounded-[var(--radius-lg)]"]').length,
      headerHeight: header ? Math.round(header.getBoundingClientRect().height) : 0,
    },
  };
}

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

/* Self-test. An audit that reports nothing is indistinguishable from an
   audit that is not looking. Plant known defects, confirm each is caught,
   then run it for real. A detector that cannot fail is not a detector. */
{
  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 1000 });
  await page.goto(`${BASE}/#/t/phishing`, { waitUntil: "domcontentloaded" });
  await new Promise((r) => setTimeout(r, 700));
  const caught = await page.evaluate(() => {
    const out = [];
    // (a) two buttons of deliberately different heights side by side
    const row = document.createElement("div");
    row.className = "flex items-center gap-2";
    row.innerHTML =
      '<button style="height:24px">a</button><button style="height:40px">b</button>';
    document.querySelector("main").appendChild(row);
    // (b) a duplicate id
    const d1 = document.createElement("div");
    d1.id = "planted-dup";
    const d2 = document.createElement("div");
    d2.id = "planted-dup";
    document.querySelector("main").append(d1, d2);
    // (c) a box that overflows its parent horizontally
    const p = document.createElement("div");
    p.style.cssText = "width:100px;overflow:visible";
    const c = document.createElement("div");
    c.style.cssText = "width:400px;height:10px";
    p.appendChild(c);
    document.querySelector("main").appendChild(p);
    // (d) two siblings that overlap
    const srow = document.createElement("div");
    srow.className = "flex items-center gap-3";
    srow.style.cssText = "position:relative;width:200px";
    srow.innerHTML =
      '<button style="width:160px;height:32px;position:absolute;left:0">l</button>' +
      '<button style="width:160px;height:32px;position:absolute;left:80">r</button>';
    document.querySelector("main").appendChild(srow);
    // (e) a percentage height with no definite ancestor
    const wrap = document.createElement("div");
    wrap.className = "flex items-end";
    const bar = document.createElement("div");
    bar.style.cssText = "height:60%;width:20px";
    wrap.appendChild(bar);
    document.querySelector("main").appendChild(wrap);
    return out;
  });
  const res = await page.evaluate(collect);
  const kinds = new Set(res.problems.map((p) => p.kind));
  const want = [
    "mixed-control-height",
    "duplicate-id",
    "overflow-parent",
    "sibling-overlap",
    "zero-height-percentage",
  ];
  const missing = want.filter((k) => !kinds.has(k));
  console.log("SELF-TEST");
  console.log(
    missing.length === 0
      ? "  pass — all planted defects detected"
      : `  FAIL — missed: ${missing.join(", ")}`,
  );
  await page.close();
}

let total = 0;
for (const [hash, name] of ROUTES) {
  for (const theme of THEMES) {
    for (const [w, h, label] of VIEWPORTS) {
      const page = await browser.newPage();
      await page.setViewport({ width: w, height: h });
      const errors = [];
      page.on("pageerror", (e) => errors.push(String(e.message)));
      page.on("console", (m) => {
        if (m.type() === "error") errors.push(m.text());
      });
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
      await new Promise((r) => setTimeout(r, 420));

      const { problems, stats } = await page.evaluate(collect);
      const unique = new Map();
      for (const p of problems) unique.set(`${p.kind}|${p.detail}`, p);
      const list = [...unique.values()];
      total += list.length;

      if (list.length || errors.length) {
        console.log(`\n=== ${name} @ ${label} ${theme} ===`);
        if (errors.length) console.log(`  RUNTIME: ${[...new Set(errors)].join(" | ")}`);
        for (const p of list) {
          console.log(`  [${p.kind}] ${p.detail}`);
          console.log(`      node:   ${p.cls}`);
          if (p.parent) console.log(`      parent: ${p.parent}`);
        }
      } else {
        console.log(
          `ok  ${name.padEnd(10)} ${label.padStart(4)} ${theme.padEnd(5)} header ${stats.headerHeight}px`,
        );
      }
      await page.close();
    }
  }
}

await browser.close();
console.log(`\nTOTAL DISTINCT PROBLEMS: ${total}`);
