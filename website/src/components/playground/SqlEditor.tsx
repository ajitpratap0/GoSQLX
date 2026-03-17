'use client';
import { useRef, useEffect } from "react";
import { EditorView, placeholder as cmPlaceholder, keymap } from "@codemirror/view";
import { EditorState } from "@codemirror/state";
import { sql } from "@codemirror/lang-sql";
import { oneDark } from "@codemirror/theme-one-dark";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import {
  syntaxHighlighting,
  defaultHighlightStyle,
  bracketMatching,
} from "@codemirror/language";

interface SqlEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  minHeight?: string;
  ariaLabel?: string;
}

const baseTheme = EditorView.theme({
  "&": {
    borderRadius: "0.5rem",
    overflow: "hidden",
  },
  "&.cm-focused": {
    outline: "2px solid #3b82f6",
  },
  ".cm-scroller": {
    fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
    fontSize: "14px",
    lineHeight: "1.6",
  },
  ".cm-gutters": {
    borderRight: "none",
  },
  ".cm-content": {
    maxWidth: "100%",
  },
  ".cm-line": {
    wordBreak: "break-all" as any,
  },
});

export default function SqlEditor({
  value,
  onChange,
  placeholder = "",
  readOnly = false,
  minHeight = "200px",
  ariaLabel = "SQL editor",
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
      ".cm-content": {
        minHeight,
      },
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

    const extensions = [
      baseTheme,
      minHeightTheme,
      oneDark,
      sql(),
      syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
      bracketMatching(),
      history(),
      keymap.of([...defaultKeymap, ...historyKeymap]),
      updateListener,
    ];

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

    return () => {
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

  return <div ref={containerRef} style={{ maxWidth: "100%", overflow: "hidden" }} aria-label={ariaLabel || placeholder || "SQL editor"} />;
}
