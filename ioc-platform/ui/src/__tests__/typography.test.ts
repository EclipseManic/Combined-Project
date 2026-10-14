/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";

// Typography floor.
//
// The UI carried 239 hand-rolled `text-[Npx]` values below Tailwind's smallest
// named step (`text-xs` = 12px), concentrated in chips, pills and meta rows. The
// named scale exists so a size is chosen from a scale; arbitrary values below it
// mean the size was picked to fit a layout rather than to be read.
//
// 12px is the floor. This test fails the build if one creeps back in.
//
// Sources are read through Vite's `import.meta.glob` rather than `node:fs`, so
// the file typechecks under the app's tsconfig without `@types/node`.

const SOURCES = import.meta.glob("/src/**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

const MIN_PX = 12;
const ARBITRARY_SIZES = /text-\[(\d+(?:\.\d+)?)px\]/g;
/** A chip, badge or pill with no vertical padding for a 12px label. */
const ZERO_PADDING_CHIP = /(?:px-1|px-1\.5|px-2)\s+py-0(?![.\d])/g;

const offenders = (
  pattern: RegExp,
  predicate: (size: string) => boolean,
): { where: string; hit: string }[] => {
  const found: { where: string; hit: string }[] = [];
  for (const [path, content] of Object.entries(SOURCES)) {
    for (const match of content.matchAll(pattern)) {
      const size = match[1] ?? match[0];
      if (!predicate(size)) continue;
      const line = content.slice(0, match.index).split("\n").length;
      found.push({ where: `${path}:${line}`, hit: match[0] });
    }
  }
  return found;
};

describe("typography floor", () => {
  it("has no text size below 12px anywhere in the UI", () => {
    const bad = offenders(ARBITRARY_SIZES, (size) => Number(size) < MIN_PX);
    expect(bad, `text below ${MIN_PX}px:\n${bad.map((o) => `${o.where}  ${o.hit}`).join("\n")}`).toEqual([]);
  });

  it("keeps chip padding above zero now that labels are 12px", () => {
    // A 12px label in a `py-0` box touches its own border.
    const bad = offenders(ZERO_PADDING_CHIP, () => true);
    expect(bad, `zero-vertical-padding chips:\n${bad.map((o) => o.where).join("\n")}`).toEqual([]);
  });

  it("uses the named scale rather than arbitrary pixel sizes", () => {
    const allowed = new Set([9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 24]);
    const bad = offenders(ARBITRARY_SIZES, (size) => !allowed.has(Number(size)));
    expect(bad, bad.map((o) => `${o.where}  ${o.hit}`).join("\n")).toEqual([]);
  });

  it("reads a non-trivial number of sources", () => {
    // Guards against the glob silently matching nothing, which would make the
    // assertions above pass vacuously.
    expect(Object.keys(SOURCES).length).toBeGreaterThan(50);
  });

  it("contains no mojibake from an encoding round-trip", () => {
    // PowerShell 5.1's `Get-Content -Raw` decodes with the system ANSI codepage,
    // not UTF-8, so a Get-Content -> Set-Content -Encoding utf8 round-trip
    // re-encodes already-correct text: a middlot becomes A-circumflex-middot,
    // an em dash becomes a-hat-euro-quotation. That silently corrupted 21 files
    // and 149 strings before it was caught.
    //
    // The pattern is written with escapes only. Spelling the mangled characters
    // literally here would put them in this file's own source, and since the
    // glob reads every source file the test would then match itself.
    const SUSPECT = /[\u00c2\u00c3]|\u00e2\u20ac|\u00c2\u00b7/g;
    const bad: string[] = [];
    for (const [path, content] of Object.entries(SOURCES)) {
      for (const match of content.matchAll(SUSPECT)) {
        const line = content.slice(0, match.index).split("\n").length;
        bad.push(`${path}:${line}  ${JSON.stringify(match[0])}`);
      }
    }
    expect(bad, `mojibake:\n${bad.join("\n")}`).toEqual([]);
  });
});
