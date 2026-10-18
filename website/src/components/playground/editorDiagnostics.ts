// In-editor parse error marker for the playground's SQL editor (#759).
//
// The WASM bridge reports where a parse error sits (ErrorSpan, see
// bridgeTypes.ts). This module turns that span into a CodeMirror lint
// diagnostic: a wavy underline (or a caret for an empty span at the end of the
// input), a gutter marker and a hover tooltip, all coloured with the site's
// design tokens so they follow the light and dark themes. The editor's content
// element gets aria-invalid and an aria-describedby message. Any edit clears
// the marker until the next parse reports a new one.
import { EditorState, Prec, StateEffect, StateField, type Extension, type Text, type TransactionSpec } from "@codemirror/state";
import { EditorView, ViewPlugin, keymap, type ViewUpdate } from "@codemirror/view";
import { diagnosticCount, lintGutter, lintKeymap, linter, setDiagnosticsEffect, type Diagnostic } from "@codemirror/lint";
import type { ErrorSpan } from "./bridgeTypes";

/** A parse error span together with the SQL it was computed for. */
export interface EditorErrorMarker {
  source: string;
  span: ErrorSpan;
}

/** Screen-reader text for the editor while a parse error is marked. */
export function describeErrorSpan(span: ErrorSpan): string {
  const code = span.code ? ` ${span.code}` : "";
  return `Parse error${code} at line ${span.line}, column ${span.column}: ${span.message}`;
}

/** Maps a 1-based line and UTF-16 column to a document offset, clamped to the text. */
function offsetOf(doc: Text, line: number, column: number): number {
  const l = doc.line(Math.min(Math.max(line, 1), doc.lines));
  return l.from + Math.min(Math.max(column - 1, 0), l.length);
}

/** The diagnostic for span in doc, with its range clamped to the document. */
export function spanToDiagnostic(doc: Text, span: ErrorSpan): Diagnostic {
  const from = offsetOf(doc, span.line, span.column);
  const to = Math.max(from, offsetOf(doc, span.end_line, span.end_column));
  return { from, to, severity: "error", source: "GoSQLX parser", message: describeErrorSpan(span) };
}

const setErrorMessage = StateEffect.define<string | null>();

// The message announced for the marked error; null when nothing is marked.
const errorMessage = StateField.define<string | null>({
  create: () => null,
  update(value, tr) {
    for (const e of tr.effects) if (e.is(setErrorMessage)) return e.value;
    return tr.docChanged ? null : value;
  },
});

// The last message announced through the live region. Unlike errorMessage it
// survives edits, so an error that is cleared by typing and then reported
// again unchanged is not announced twice; it resets when a parse succeeds.
const announcedMessage = StateField.define<string | null>({
  create: () => null,
  update(value, tr) {
    for (const e of tr.effects) if (e.is(setErrorMessage)) return e.value;
    return value;
  },
});

// Edits invalidate the marker: drop it in the same transaction as the change.
const clearOnEdit = EditorState.transactionExtender.of((tr) =>
  tr.docChanged && diagnosticCount(tr.startState) > 0 ? { effects: setDiagnosticsEffect.of([]) } : null,
);

let nextDescriptionId = 0;

// Visually hidden elements: one holds the message and is referenced by
// aria-describedby; a polite live region announces each newly found error
// once, so screen-reader users hear about it while typing.
const description = ViewPlugin.fromClass(
  class {
    readonly dom: HTMLElement;
    readonly live: HTMLElement;
    constructor(view: EditorView) {
      this.dom = document.createElement("span");
      this.dom.id = `sql-editor-error-${++nextDescriptionId}`;
      this.dom.className = "cm-sr-only";
      this.dom.textContent = view.state.field(errorMessage) ?? "";
      this.live = document.createElement("span");
      this.live.className = "cm-sr-only";
      this.live.setAttribute("role", "status");
      this.live.setAttribute("aria-live", "polite");
      view.dom.append(this.dom, this.live);
    }
    update(update: ViewUpdate) {
      const message = update.state.field(errorMessage);
      if (message !== update.startState.field(errorMessage)) this.dom.textContent = message ?? "";
      const announced = update.state.field(announcedMessage);
      if (announced !== update.startState.field(announcedMessage)) this.live.textContent = announced ?? "";
    }
    destroy() {
      this.dom.remove();
      this.live.remove();
    }
  },
  {
    provide: (plugin) =>
      EditorView.contentAttributes.of((view): Record<string, string> => {
        const message = view.state.field(errorMessage);
        const id = view.plugin(plugin)?.dom.id;
        return message && id ? { "aria-invalid": "true", "aria-describedby": id } : {};
      }),
  },
);

// Token colours replace @codemirror/lint's fixed reds so the marker meets
// contrast in both themes.
const markerTheme = EditorView.theme({
  ".cm-lintRange-error": {
    backgroundImage: "none",
    textDecorationLine: "underline",
    textDecorationStyle: "wavy",
    textDecorationColor: "var(--danger)",
    textDecorationThickness: "1.5px",
    textUnderlineOffset: "3px",
    textDecorationSkipInk: "none",
  },
  ".cm-lintPoint-error:after": {
    left: "-4px",
    borderLeftWidth: "5px",
    borderRightWidth: "5px",
    borderBottom: "6px solid var(--danger)",
  },
  ".cm-lint-marker-error": {
    content: "none",
    width: "0.7em",
    height: "0.7em",
    margin: "0.15em",
    borderRadius: "50%",
    backgroundColor: "var(--danger)",
  },
  // @codemirror/lint renders the hover tooltip as ul.cm-tooltip-lint inside a
  // separate .cm-tooltip wrapper, so the surface is set on that wrapper.
  ".cm-tooltip:has(> .cm-tooltip-lint)": {
    backgroundColor: "var(--bg-raised)",
    color: "var(--fg)",
    border: "1px solid var(--border)",
    borderRadius: "0.375rem",
    overflow: "hidden",
  },
  ".cm-tooltip-lint": { backgroundColor: "var(--bg-raised)", color: "var(--fg)" },
  ".cm-diagnostic-error": { borderLeft: "4px solid var(--danger)" },
  ".cm-diagnosticSource": { color: "var(--fg-muted)", opacity: "1" },
  ".cm-panels": { backgroundColor: "var(--bg-raised)", color: "var(--fg)" },
  ".cm-panels-bottom": { borderTop: "1px solid var(--border)" },
  // The base theme colours the selected row light blue (#ddd unfocused,
  // Highlight while the list has focus); both states use tokens instead, with
  // an accent bar marking the focused list.
  ".cm-panel.cm-panel-lint ul [aria-selected], .cm-panel.cm-panel-lint ul:focus [aria-selected]": {
    backgroundColor: "var(--bg-overlay)",
    color: "var(--fg)",
  },
  ".cm-panel.cm-panel-lint ul:focus [aria-selected]": { boxShadow: "inset 3px 0 0 var(--accent)" },
  ".cm-panel.cm-panel-lint ul [aria-selected] .cm-diagnosticSource": { color: "var(--fg-muted)" },
  ".cm-sr-only": {
    position: "absolute",
    width: "1px",
    height: "1px",
    padding: "0",
    margin: "-1px",
    overflow: "hidden",
    clip: "rect(0, 0, 0, 0)",
    whiteSpace: "nowrap",
    border: "0",
  },
});

/** Editor extensions that display a parse error marker. */
export function parseErrorMarker(): Extension {
  return [
    linter(null, { autoPanel: false }),
    lintGutter(),
    keymap.of(lintKeymap),
    errorMessage,
    announcedMessage,
    clearOnEdit,
    description,
    // Above oneDark, whose own panel colours would otherwise win in dark mode.
    Prec.highest(markerTheme),
  ];
}

/** The last message announced through the live region, or null after a successful parse. */
export function announcedErrorMessage(state: EditorState): string | null {
  return state.field(announcedMessage, false) ?? null;
}

/** The announced message for the marked parse error, or null when none is marked. */
export function markedErrorMessage(state: EditorState): string | null {
  return state.field(errorMessage, false) ?? null;
}

/**
 * The transaction that shows marker in the editor (or clears it when null).
 * Returns null when nothing needs to change, when the editor has no
 * parseErrorMarker() extension, or when the marker was
 * computed for different SQL than the editor now holds: the user has typed
 * since, and the next parse will report a fresh position.
 */
export function errorMarkerTransaction(state: EditorState, marker: EditorErrorMarker | null): TransactionSpec | null {
  const current = state.field(errorMessage, false);
  // The editor was built without parseErrorMarker() (e.g. a read-only pane).
  if (current === undefined) return null;
  if (!marker) {
    return current === null && diagnosticCount(state) === 0 && state.field(announcedMessage, false) == null
      ? null
      : { effects: [setDiagnosticsEffect.of([]), setErrorMessage.of(null)] };
  }
  if (state.doc.toString() !== marker.source) return null;
  return {
    effects: [
      setDiagnosticsEffect.of([spanToDiagnostic(state.doc, marker.span)]),
      setErrorMessage.of(describeErrorSpan(marker.span)),
    ],
  };
}
