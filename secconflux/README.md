# SecConflux

Unified SecOps utility. Five security tools, one interface, one design language.

This directory currently holds **the complete frontend only**. The five backends
are not connected yet — every tool page renders from realistic fixtures shaped
after each backend's real response, so the UI can be reviewed and agreed on
before any wiring happens.

## Run it

```
python run.py
```

Opens <http://127.0.0.1:7000/> and prints the URL. If 7000 is busy it takes the
next free port and tells you which one, so the address you open is always the
address it is actually serving.

Useful flags: `--no-browser`, `--port 8080`, `--verbose`.

## What is here

```
run.py                  launcher: serves ui/dist, opens a browser
ui/
  index.html            single document; theme applied before first paint
  vite.config.ts        React + Tailwind 4, port 7000, @ -> src
  audit.mjs             layout audit, with a self-test
  navtest.mjs           clicks every tab and chip
  shots.mjs             screenshots
  src/
    styles/tokens.css   THE design system. One token layer, light and dark.
    lib/
      tools.ts          the tool registry and the navigation model
      icons.tsx         one inline icon set
      router.ts         hash router, and why it is hash-based
      shell-context.tsx active tool, main tab, chip, theme, palette, tour
      useEdgeFade.ts    fades a scrollable strip only where it is clipped
      utils.ts          formatting, clipboard, download
    ui/index.tsx        the shared component vocabulary every tool renders from
    shell/
      chrome.tsx        header, brand switcher, command palette, toasts,
                        error boundary
      tour.tsx          the first-run tour
    pages/
      Landing.tsx       the SecConflux marketing page
      tools/
        ToolOverview.tsx the shared "what is this tool" page
        Malware.tsx  Ioc.tsx  Events.tsx  Phishing.tsx  RuleForge.tsx
    data/fixtures.ts    realistic fixtures per backend response shape
```

## The two decisions that matter

**One token layer, not five.** Every tool reads colour, type, spacing, radius
and motion from `styles/tokens.css`. A tool does not have its own CSS and cannot
drift from the others without editing that one file.

Element resets live in `@layer base`. That is not tidiness: `@import
"tailwindcss"` opens `@layer theme, base, components, utilities`, and
*unlayered* CSS outranks all of them. An unlayered
`button { background: none; border: none; padding: 0 }` silently defeats
`bg-*`, `border` and `px-*` on every button in the product. It produced buttons
with no fill, no border and no horizontal padding, which reads as "misaligned"
rather than as a cascade bug — the height still came from `h-8`, so the box
looked right while its contents did not.

**Accent is a runtime variable, not a build-time one.** `<html data-tool="ioc">`
sets `--tool-accent` and the entire product re-tints. That is how five tools
share one design language and still look like five different tools. The hues:

| Tool | Hue |
|---|---|
| Home | violet → cyan |
| Malware Analyzer | indigo → purple |
| IOC Lookup | amber → orange |
| Event Analyzer | sky → cyan |
| Phishing Detector | rose → pink |
| RuleForge | teal → emerald |

## The header

Two rows, both inside the same sticky bar.

```
row 1   [brand ▾]      Dashboard | Investigation      [New Scan]  [☀]
row 2              Summary  Static  Intel  Behavioral  IOCs
```

Row 1 is a 3-track grid: `minmax(0,1fr) minmax(0,auto) minmax(0,1fr)`. Equal
side tracks are what make the centre genuinely centred; a `flex-1` middle track
absorbs whatever the outer two do not and centres in the leftover space, which
put every tab about 70px right of true centre.

Row 2 is the section chips, centred across the full header width, directly under
the main tabs. They had a row of their own because on a shared row the chips and
the action button end up adjacent and neither reads as a different level — the
header becomes one undifferentiated strip running from the centre of the screen
to the right edge.

The two levels are deliberately unequal. Main tabs are filled pills; chips are
text with an underline. When both were pills the header read as ten peers.

Below 1280 the chips collapse into a labelled menu. Hiding them outright looks
tidier in a screenshot and is a dead end in use.

`surface` on every chip is declared rather than inferred. A chip click reveals
the surface it names, because RuleForge's dialect reference belongs to the
Studio and not to History, and inferring that from position put the wrong screen
behind the wrong tab.

## What each tab is for

**Tab 1 is a description of the tool. Tab 2 is the tool.**

`pages/tools/ToolOverview.tsx` is one component used by all five, for the same
reason the design system is one file: five hand-written "about" pages drift in
structure first and in tone second. It answers four questions in the same order
every time — what is this, how does it work, what does it do, how do I use it —
plus a **"what it does not do"** section, because a tool that admits its limits
is more usable than one that claims coverage it does not have.

### The section chips are the original tools' own tabs

Copied out of each tool's source, verbatim, in the original order. Nothing here
is invented and nothing is renamed:

| Tool | Tab 1 | Tab 2 | Section chips |
|---|---|---|---|
| Malware Analyzer | Overview | Investigation | Dashboard, Static Analysis, Threat Intel, Behavioral, IOCs |
| IOC Lookup | Overview | Lookup | Lookup, Investigations, Batch, History |
| Event Analyzer | Overview | Investigation | Events, IOCs, Sigma, Notes |
| Phishing Detector | Overview | Analysis | Dashboard, Sender & Auth, Headers, Artifacts |
| RuleForge | Overview | Workshop | Author, Tune, Debug, Understand, History, Dialects |

Sources: `Malware Analyzer/ui/index.html:281-300`,
`ioc-platform/ui/src/App.tsx:26-32`, `Event-Analyzer/app/templates/index.html:25-51`,
`Phishing-Mail-Detector/templates/index.html:458,602-604`,
`RuleForge/templates/workshop.html:6-9`.

An earlier pass shortened "Static Analysis" to "Static", renamed "Threat Intel"
to "Intel", gave Event Analyzer a Timeline, a Channels tab and a Bookmarks tab
that the tool never had, dropped its Notes tab which it did have, and gave
RuleForge a duplicate job picker alongside the header chips. That is what made
the tools stop feeling like themselves. Only the theme, the colour and the box
treatment are SecConflux; the structure belongs to the tools.

## Navigation

Six ways to move, all working:

- the tool switcher at the top left, present on every screen
- `Ctrl`/`Cmd` + `M` command palette, from anywhere
- keys `1`–`5` for the five tools, from anywhere
- the tool cards on the landing page
- `?` reopens the tour
- cross-tool links, e.g. a sample's IOCs into IOC Lookup

Hash routing is deliberate. When the backends are wired in they mount under
`/tool/<id>/` on this same origin, and a history router would own the entire
path namespace and make every one of those mounts a negotiation. The hash
keeps the shell's routes in a namespace that cannot collide.

## Verification

Three scripts, and the first one proves the other two can fail.

```
npm run verify     # typecheck, build, layout audit, navigation test
npm run audit      # layout audit across 5 widths x 2 themes x 6 routes
npm run navtest    # clicks every tab and chip, asserts the page changed
npm run shots      # screenshots to shots/
```

`audit.mjs` plants known defects in the page and fails if it does not detect
each one. It caught three bugs in itself this way: `parseFloat("visible")` is
NaN so the overflow check could never fire; `getComputedStyle().height`
returns used pixels so the collapsed-chart check never fired; and walking up
from a tab to find "the rail" landed on the centre group. An audit that cannot
fail is not a detector.

`navtest.mjs` exists because measuring cannot find a chip that renders nothing.
A chip whose id does not match the render switch produces no error and no
warning — just a blank page.

## Status

- `tsc --noEmit` clean, `noUnusedLocals` on
- `npm run build` passes, 37 kB CSS / 447 kB JS
- layout audit: 0 problems across 1920 / 1440 / 1280 / 1024 / 768, dark + light
- navigation test: 21 checks, 0 failures

Not built yet, and deliberately so:

- any call to a real backend
- unified persistence across the five stores
- the backends themselves
