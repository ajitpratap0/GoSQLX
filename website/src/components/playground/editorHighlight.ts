// GoSQLX-powered syntax highlighting for the playground's SQL editor.
//
// Once the WASM parser is loaded, the editor asks it (gosqlxHighlight, see
// wasm/internal/bridge/highlight.go) to classify the SQL and marks each span
// with a `cm-gsx-<category>` class, coloured with the site's AA-checked design
// tokens (the same mapping as the Shiki code blocks in globals.css), so the
// colours follow the light and dark themes. Requests are debounced on edits;
// between requests the previous marks are mapped through the changes.
//
// The state field holds null while GoSQLX highlighting is inactive: before a
// source is configured, while the first request is pending, or after a
// request failed. The editor keeps its Lezer highlighting in that state and
// drops it while marks are shown (see highlightActivation), so text is never
// coloured twice.
import {
  Facet,
  RangeSetBuilder,
  StateEffect,
  StateField,
  type EditorState,
  type Extension,
  type Transaction,
} from "@codemirror/state";
import { Decoration, EditorView, ViewPlugin, type DecorationSet, type ViewUpdate } from "@codemirror/view";
import type { HighlightCategory, HighlightSpan } from "./bridgeTypes";

/**
 * Classifies sql, synchronously or asynchronously. Returns (or resolves to)
 * null, or throws (rejects), when highlighting is unavailable, which keeps
 * the editor's fallback highlighting.
 */
export type HighlightSource = (
  sql: string,
) => readonly HighlightSpan[] | null | Promise<readonly HighlightSpan[] | null>;

/** Delay between the last edit and the next highlight request. */
export const HIGHLIGHT_DEBOUNCE_MS = 120;

/**
 * Longest document (in UTF-16 units) GoSQLX highlights. Each request
 * classifies the whole document, so larger documents keep the editor's Lezer
 * highlighting instead of making highlighting lag far behind typing.
 */
export const MAX_HIGHLIGHT_LENGTH = 200_000;

const CATEGORIES: ReadonlySet<string> = new Set<HighlightCategory>([
  "keyword",
  "function",
  "type",
  "identifier",
  "quoted-identifier",
  "string",
  "number",
  "constant",
  "operator",
  "punctuation",
  "comment",
  "placeholder",
  "error",
]);

/** The mark class for a category, or null for categories this editor does not know. */
export function highlightClass(category: string): string | null {
  return CATEGORIES.has(category) ? `cm-gsx-${category}` : null;
}

/** A decoration range: offsets into the document and the class to apply. */
export interface HighlightMark {
  from: number;
  to: number;
  className: string;
}

/**
 * Converts bridge spans to mark ranges for a document of docLength UTF-16
 * units. Ranges are clamped to the document; empty ranges, unknown
 * categories, and spans that are out of order or overlap the previous one
 * are dropped, so the result is sorted and non-overlapping.
 */
export function spansToMarks(spans: readonly HighlightSpan[], docLength: number): HighlightMark[] {
  const marks: HighlightMark[] = [];
  let last = 0;
  for (const span of spans) {
    const className = highlightClass(span.category);
    if (!className || !Number.isFinite(span.start) || !Number.isFinite(span.end)) continue;
    const from = Math.min(Math.max(Math.trunc(span.start), 0), docLength);
    const to = Math.min(Math.max(Math.trunc(span.end), 0), docLength);
    if (to <= from || from < last) continue;
    marks.push({ from, to, className });
    last = to;
  }
  return marks;
}

const markCache = new Map<string, Decoration>();

function markFor(className: string): Decoration {
  let mark = markCache.get(className);
  if (!mark) {
    mark = Decoration.mark({ class: className });
    markCache.set(className, mark);
  }
  return mark;
}

/** Builds the decoration set for sorted, non-overlapping marks (see spansToMarks). */
export function marksToDecorations(marks: readonly HighlightMark[]): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>();
  for (const m of marks) builder.add(m.from, m.to, markFor(m.className));
  return builder.finish();
}

/** The decorations for spans classifying sql, or null for a malformed result. */
function spansToHighlight(spans: unknown, sql: string): DecorationSet | null {
  if (!Array.isArray(spans)) return null;
  return marksToDecorations(spansToMarks(spans, sql.length));
}

/**
 * Runs source on sql and returns (or resolves to) the decorations to show,
 * or null when GoSQLX highlighting is unavailable (no source, sql longer than
 * MAX_HIGHLIGHT_LENGTH, a thrown error or rejection, or a malformed result).
 * The result is a promise exactly when source returned one.
 */
export function computeHighlight(
  source: HighlightSource | null,
  sql: string,
): DecorationSet | null | Promise<DecorationSet | null> {
  if (!source || sql.length > MAX_HIGHLIGHT_LENGTH) return null;
  let spans: ReturnType<HighlightSource>;
  try {
    spans = source(sql);
  } catch {
    return null;
  }
  if (spans instanceof Promise) {
    return spans.then(
      (resolved) => spansToHighlight(resolved, sql),
      () => null,
    );
  }
  return spansToHighlight(spans, sql);
}

const highlightSource = Facet.define<HighlightSource | null, HighlightSource | null>({
  combine: (values) => (values.length > 0 ? values[values.length - 1] : null),
});

/** Configures where the editor gets highlight spans from; null disables GoSQLX highlighting. */
export function gosqlxHighlightSource(source: HighlightSource | null): Extension {
  return highlightSource.of(source);
}

/** Replaces the GoSQLX marks; null deactivates GoSQLX highlighting. */
export const setHighlight = StateEffect.define<DecorationSet | null>();

const highlightField = StateField.define<DecorationSet | null>({
  create: () => null,
  update(value, tr) {
    for (const e of tr.effects) if (e.is(setHighlight)) return e.value;
    return value && tr.docChanged ? value.map(tr.changes) : value;
  },
  provide: (field) => EditorView.decorations.from(field, (value) => value ?? Decoration.none),
});

/** The GoSQLX marks shown in state, or null while GoSQLX highlighting is inactive. */
export function gosqlxHighlightMarks(state: EditorState): DecorationSet | null {
  return state.field(highlightField, false) ?? null;
}

/** Whether GoSQLX marks are currently shown, so fallback highlighting must be off. */
export function isGosqlxHighlightActive(state: EditorState): boolean {
  return gosqlxHighlightMarks(state) !== null;
}

/**
 * The activation state tr leaves GoSQLX highlighting in when it changes it,
 * or null when tr leaves it unchanged. Lets the editor swap its fallback
 * highlighting in the same transaction.
 */
export function highlightActivation(tr: Transaction): boolean | null {
  let next: boolean | null = null;
  for (const e of tr.effects) if (e.is(setHighlight)) next = e.value !== null;
  if (next === null || next === isGosqlxHighlightActive(tr.startState)) return null;
  return next;
}

// Requests spans when the source changes (immediately) and after edits
// (debounced). Dispatches from a timer or a resolved request, never during an
// update. An asynchronous answer is dropped when a newer request was made or
// the document changed meanwhile; the newer request replaces it.
const refresher = ViewPlugin.fromClass(
  class {
    private readonly view: EditorView;
    private timer: ReturnType<typeof setTimeout> | null = null;
    private request = 0;
    private destroyed = false;

    // No parameter properties: Node's type stripping (npm test) rejects them.
    constructor(view: EditorView) {
      this.view = view;
      this.schedule(0);
    }

    update(update: ViewUpdate) {
      if (update.startState.facet(highlightSource) !== update.state.facet(highlightSource)) {
        this.schedule(0);
      } else if (update.docChanged) {
        this.schedule(HIGHLIGHT_DEBOUNCE_MS);
      }
    }

    private schedule(delay: number) {
      if (this.timer) clearTimeout(this.timer);
      this.timer = setTimeout(() => {
        this.timer = null;
        this.refresh();
      }, delay);
    }

    private refresh() {
      const state = this.view.state;
      const source = state.facet(highlightSource);
      const request = ++this.request;
      // Skip serialising a document too large to highlight (see MAX_HIGHLIGHT_LENGTH).
      const next = state.doc.length > MAX_HIGHLIGHT_LENGTH ? null : computeHighlight(source, state.doc.toString());
      if (!(next instanceof Promise)) {
        this.apply(next);
        return;
      }
      const doc = state.doc;
      void next.then((decorations) => {
        if (this.destroyed || request !== this.request || this.view.state.doc !== doc) return;
        this.apply(decorations);
      });
    }

    private apply(next: DecorationSet | null) {
      if (next === null && !isGosqlxHighlightActive(this.view.state)) return;
      this.view.dispatch({ effects: setHighlight.of(next) });
    }

    destroy() {
      this.destroyed = true;
      if (this.timer) clearTimeout(this.timer);
    }
  },
);

// Same token mapping as the .shiki code blocks in globals.css; every colour is
// a text token that scripts/check-contrast.mjs holds to WCAG AA on the pane
// surfaces in both themes. Identifiers keep the editor's foreground colour.
const highlightTheme = EditorView.baseTheme({
  ".cm-gsx-keyword": { color: "var(--accent)" },
  ".cm-gsx-function": { color: "var(--accent-warm)" },
  ".cm-gsx-type": { color: "var(--violet)" },
  ".cm-gsx-quoted-identifier": { color: "var(--info)" },
  ".cm-gsx-string": { color: "var(--ok)" },
  ".cm-gsx-number, .cm-gsx-constant": { color: "var(--cyan)" },
  ".cm-gsx-operator, .cm-gsx-punctuation": { color: "var(--fg-muted)" },
  ".cm-gsx-comment": { color: "var(--fg-subtle)", fontStyle: "italic" },
  ".cm-gsx-placeholder": { color: "var(--warn)" },
  ".cm-gsx-error": { color: "var(--danger)" },
});

/**
 * GoSQLX highlighting: the marks, the request scheduler and their colours.
 * Pair it with gosqlxHighlightSource to supply spans.
 */
export function gosqlxHighlighting(): Extension {
  return [highlightField, refresher, highlightTheme];
}
