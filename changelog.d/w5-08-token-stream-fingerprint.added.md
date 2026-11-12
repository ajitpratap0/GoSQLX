- **Fingerprint modes and dialect options [W5-08]**: `fingerprint.Options`,
  `Mode`, `NormalizeWithOptions` and `FingerprintWithOptions` support
  token-stream and legacy normalisation with dialect selection in both modes;
  `VersionOf`, `Version`, `VersionPrefix` and `ErrEmpty` expose the version and
  empty-input contract. The `gosqlx` package adds no options
  entry points; import `pkg/fingerprint` for `ModeLegacy` (the v1.17 output and
  syntax-error contract) and dialect selection.
