- **Fingerprint modes and dialect options [W5-08]**: `fingerprint.Options`,
  `Mode`, `NormalizeWithOptions` and `FingerprintWithOptions` support
  token-stream and legacy normalisation with dialect selection in both modes;
  `VersionOf`, `Version`, `VersionPrefix` and `ErrEmpty` expose the version and
  empty-input contract. `gosqlx.NormalizeWithOptions` and
  `gosqlx.FingerprintWithOptions` accept the same `fingerprint.Options`, including
  `ModeLegacy` for the v1.17 output and syntax-error contract.
