// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

//go:build race

package transpiler

// raceDetector reports whether the race detector instruments this test binary
// (internal-package twin of raceEnabled in the transpiler_test package).
const raceDetector = true
