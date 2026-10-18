'use client';
import { useRef, useEffect, type MouseEvent as ReactMouseEvent } from "react";
import { EditorView, placeholder as cmPlaceholder, keymap } from "@codemirror/view";
import { EditorState, Compartment, Prec } from "@codemirror/state";
import { sql } from "@codemirror/lang-sql";
import { oneDark } from "@codemirror/theme-one-dark";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import {
  syntaxHighlighting,
  defaultHighlightStyle,
  bracketMatching,
  HighlightStyle,
} from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { errorMarkerTransaction, parseErrorMarker, type EditorErrorMarker } from "./editorDiagnostics";

// Override oneDark's coral (#e06c75) which fails WCAG AA (4.38:1 on #282c34).
// #e87980 achieves ~5.07:1 contrast against #282c34.
const accessibleHighlight = HighlightStyle.define([
  { tag: [tags.name, tags.deleted, tags.character, tags.propertyName, tags.macroName], color: "#e87980" },
]);

interface SqlEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  minHeight?: string;
  ariaLabel?: string;
  /** Parse error to mark in the editor; cleared on the next edit. */
  errorMarker?: EditorErrorMarker | null;
}

const baseTheme = EditorView.theme({
  "&": {
    height: "100%",
    borderRadius: "0.5rem",
    overflow: "hidden",
  },
  "&.cm-focused": {
    outline: "2px solid var(--accent)",
  },
  ".cm-scroller": {
    overflow: "auto",
    fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
    fontSize: "14px",
    lineHeight: "1.6",
    // Stretch .cm-content to the full pane so a click below the last line
    // lands in the editable area and focuses the editor.
    alignItems: "stretch",
  },
  ".cm-gutters": {
    borderRight: "none",
  },
  ".cm-content": {
    maxWidth: "100%",
  },
});

// Page background from design tokens so the editor blends into the playground.
// In light mode no base theme is applied, so the editor falls back to
// CodeMirror's light defaults plus these token colours.
const tokenTheme = (dark: boolean) =>
  Prec.highest(EditorView.theme(
    {
      "&": { backgroundColor: "var(--bg)", color: "var(--fg)" },
      ".cm-gutters": { backgroundColor: "var(--bg)", color: "var(--fg-subtle)", border: "none" },
      ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "var(--bg-overlay)" },
      ".cm-cursor": { borderLeftColor: "var(--fg)" },
    },
    { dark },
  ));

const isLightMode = () =>
  typeof document !== "undefined" && document.documentElement.classList.contains("light");

const themeExtensions = (light: boolean) =>
  light
    ? [tokenTheme(false)]
    : [syntaxHighlighting(accessibleHighlight), oneDark, tokenTheme(true)];

export default function SqlEditor({
  value,
  onChange,
  placeholder = "",
  readOnly = false,
  minHeight = "200px",
  ariaLabel = "SQL editor",
  errorMarker = null,
}: SqlEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Keep onChange ref current without recreating the editor
  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    if (!containerRef.current) return;

    const minHeightTheme = EditorView.theme({
      ".cm-scroller": {
        minHeight,
      },
    });

    const updateListener = EditorView.updateListener.of((update) => {
      if (update.docChanged) {
        if (debounceRef.current) {
          clearTimeout(debounceRef.current);
        }
        debounceRef.current = setTimeout(() => {
          onChangeRef.current(update.state.doc.toString());
        }, 200);
      }
    });

    const themeCompartment = new Compartment();
    const extensions = [
      baseTheme,
      minHeightTheme,

      themeCompartment.of(themeExtensions(isLightMode())),
      sql(),
      syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
      bracketMatching(),
      history(),
      keymap.of([...defaultKeymap, ...historyKeymap]),
      EditorView.contentAttributes.of({ "aria-label": ariaLabel }),
      updateListener,
    ];

    // Only the editable input marks parse errors; the read-only output pane
    // would otherwise carry an empty lint gutter and unused key bindings.
    if (!readOnly) {
      extensions.push(parseErrorMarker());
    }

    if (placeholder) {
      extensions.push(cmPlaceholder(placeholder));
    }

    if (readOnly) {
      extensions.push(EditorState.readOnly.of(true));
      extensions.push(EditorView.editable.of(false));
    }

    const state = EditorState.create({
      doc: value,
      extensions,
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    // Follow the site theme toggle (ThemeToggle flips the `light` class on <html>).
    const observer = new MutationObserver(() => {
      view.dispatch({
        effects: themeCompartment.reconfigure(themeExtensions(isLightMode())),
      });
    });
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    return () => {
      observer.disconnect();
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
      view.destroy();
      viewRef.current = null;
    };
    // Only recreate on readOnly/placeholder/minHeight changes, not on value
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly, placeholder, minHeight]);

  // Sync external value changes without recreating the editor
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;

    const currentDoc = view.state.doc.toString();
    if (currentDoc !== value) {
      view.dispatch({
        changes: {
          from: 0,
          to: currentDoc.length,
          insert: value,
        },
      });
    }
  }, [value]);

  // Show (or clear) the parse error marker. Declared after the value sync so a
  // marker computed for new external text is applied to that text.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const tr = errorMarkerTransaction(view.state, errorMarker);
    if (tr) view.dispatch(tr);
  }, [errorMarker]);

  // Clicks on the pane padding (outside .cm-editor) also focus the editor.
  const focusOnPaneClick = (e: ReactMouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget && !readOnly) {
      e.preventDefault();
      viewRef.current?.focus();
    }
  };

  return <div ref={containerRef} onMouseDown={focusOnPaneClick} className="h-full" style={{ maxWidth: "100%", overflow: "hidden" }} aria-label={ariaLabel} />;
}
