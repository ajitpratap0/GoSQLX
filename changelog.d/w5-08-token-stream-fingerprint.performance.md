- **Token-stream Normalize and Fingerprint [W5-08]**: defaults tokenize once,
  normalize into a pooled byte buffer and hash its bytes directly for
  fingerprints. On the layout-randomized amd64 CI
  gate, `Normalize` is 72.95% (simple_select), 59.46% (join) and 61.02% (complex)
  faster; allocs/op fall from 7/23/68 to 1 and B/op by 94% to 96%.
