- **Linter rule resource lifetime**: `LintString` and all convenience wrappers
  now release the parsed AST and recycle token storage after checking every rule
  set, including custom, configured, subset and empty sets. AST nodes,
  `Context.Nodes()` slices/elements, token slices/elements and `Word` pointers
  are borrowed only during each `Rule.Check`. Retaining them through a saved
  context, visitor, closure, background goroutine or state later used by `Fix`
  is no longer supported; Go signatures and violation outputs are unchanged.
  - **Migration:** materialize strings such as `tok.Token.Value` or
    `tok.Token.Word.Value` (after a nil check), scalars and value locations
    during `Check`, or make independently owned deep copies. Shallow token or
    slice copies can retain pooled pointers. Join all goroutines using borrowed
    resources before `Check` returns. Have `Fix` use its SQL argument and
    materialized violations instead of references saved by `Check`.
