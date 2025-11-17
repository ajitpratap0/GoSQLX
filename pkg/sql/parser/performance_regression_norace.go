//go:build !race
// +build !race

package parser

// raceEnabled is set to false when the race detector is not enabled
//
//nolint:unused // Used conditionally based on build tags
const raceEnabled = false
