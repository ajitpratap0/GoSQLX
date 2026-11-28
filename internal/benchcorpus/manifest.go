// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package benchcorpus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestPaths returns every file the manifest pins, relative to testdata/
// and sorted: all corpus .sql files, known_failures.txt and the portable
// query list.
func ManifestPaths(root string) ([]string, error) {
	var paths []string
	for _, c := range Corpora {
		files, err := CorpusFiles(root, c)
		if err != nil {
			return nil, err
		}
		paths = append(paths, files...)
	}
	paths = append(paths, KnownFailuresFile, PortableQueriesFile)
	sort.Strings(paths)
	return paths, nil
}

// BuildManifest hashes the pinned files. The result is in sha256sum format
// ("<hex>  <path>"), so `cd testdata && shasum -a 256 -c bench/MANIFEST.sha256`
// verifies it too.
func BuildManifest(root string) (string, error) {
	paths, err := ManifestPaths(root)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(root, "testdata", filepath.FromSlash(rel)))
		if err != nil {
			return "", fmt.Errorf("benchcorpus: hash %s: %w", rel, err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), rel)
	}
	return b.String(), nil
}

// Verify compares the committed manifest with the files on disk and reports
// every added, removed or changed file.
func Verify(root string) error {
	want, err := os.ReadFile(filepath.Join(root, "testdata", filepath.FromSlash(ManifestFile)))
	if err != nil {
		return fmt.Errorf("benchcorpus: read manifest: %w", err)
	}
	got, err := BuildManifest(root)
	if err != nil {
		return err
	}
	if string(want) == got {
		return nil
	}
	wm, gm := parseManifest(string(want)), parseManifest(got)
	var diffs []string
	for p, h := range gm {
		switch wh, ok := wm[p]; {
		case !ok:
			diffs = append(diffs, "not in manifest: "+p)
		case wh != h:
			diffs = append(diffs, "content changed: "+p)
		}
	}
	for p := range wm {
		if _, ok := gm[p]; !ok {
			diffs = append(diffs, "listed but missing: "+p)
		}
	}
	sort.Strings(diffs)
	if len(diffs) == 0 {
		diffs = append(diffs, "manifest is not in canonical sorted form")
	}
	return fmt.Errorf("benchcorpus: testdata/%s is stale (regenerate: go test ./internal/benchcorpus -run TestManifest -update-manifest):\n  %s",
		ManifestFile, strings.Join(diffs, "\n  "))
}

func parseManifest(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if hash, path, ok := strings.Cut(line, "  "); ok {
			m[path] = hash
		}
	}
	return m
}
