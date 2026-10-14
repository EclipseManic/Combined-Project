import type { PayloadRow, PayloadSection } from "../lib/rawPayload";
import { buildPayloadSections, countPayloadFields, limitPayloadSections } from "../lib/rawPayload";

function Row({ row, depth = 0 }: { row: PayloadRow; depth?: number }) {
  const indent = depth > 0 ? "border-l border-border pl-2.5" : "";
  const label = (
    <dt className="truncate text-text-secondary" title={row.label}>
      {row.label}
    </dt>
  );

  const value = row.flag ? (
    <dd className="font-semibold text-amber-300">{row.value}</dd>
  ) : row.muted ? (
    <dd className="text-text-secondary">{row.value}</dd>
  ) : (
    <dd className="break-words text-text-primary">{row.value}</dd>
  );

  return (
    <div className="contents">
      {label}
      {value}
      {row.truncated && (
        <>
          <dt className="text-text-secondary" />
          <dd className="text-xs italic text-text-secondary">more values hidden</dd>
        </>
      )}
      {row.items && row.items.length > 0 && (
        <>
          <dt className="sr-only">{row.label}</dt>
          <dd className="col-span-1 min-w-0">
            <ul className="flex flex-wrap gap-1">
              {row.items.map((item, index) => (
                <li
                  key={`${row.label}-${index}`}
                  className="max-w-full truncate rounded border border-border bg-bg-elevated px-1.5 py-0.5 text-xs text-text-primary"
                  title={item}
                >
                  {item}
                </li>
              ))}
            </ul>
          </dd>
        </>
      )}
      {row.children && row.children.length > 0 && (
        <div className={`col-span-2 ${indent}`}>
          <dl className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
            {row.children.map((child, index) => (
              <Row key={`${child.label}-${index}`} row={child} depth={depth + 1} />
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

function Section({ section }: { section: PayloadSection }) {
  if (section.rows.length === 0) return null;
  return (
    <section>
      <h5 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-text-secondary">
        {section.label}
      </h5>
      <dl className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        {section.rows.map((row, index) => (
          <Row key={`${row.label}-${index}`} row={row} />
        ))}
      </dl>
    </section>
  );
}

/**
 * Renders any provider's `raw_data` as labelled fields.
 *
 * This is the generic path that lets a provider's response be read without
 * opening a JSON blob. It is provider-agnostic by construction, so adapters
 * that were never anticipated still display their data.
 */
export default function PayloadFields({ raw }: { raw: unknown }) {
  const all = buildPayloadSections(raw);
  if (all.length === 0) return null;
  const { sections, hidden } = limitPayloadSections(all);
  const total = countPayloadFields(all);

  return (
    <div className="space-y-3">
      <div className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
        Provider data · {total} field{total === 1 ? "" : "s"}
      </div>
      {sections.map((section) => (
        <Section key={section.label} section={section} />
      ))}
      {hidden > 0 && (
        <p className="text-xs italic text-text-secondary">
          {hidden} more field{hidden === 1 ? "" : "s"} not shown — open the raw JSON below.
        </p>
      )}
    </div>
  );
}
