// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Command changelog validates, previews, and collects per-change release notes.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sections = []struct{ key, heading string }{
	{"breaking-changes", "Breaking Changes"}, {"added", "Added"},
	{"changed", "Changed"}, {"performance", "Performance"},
	{"behavior-changes", "Behavior changes"}, {"deprecated", "Deprecated"},
	{"removed", "Removed"}, {"fixed", "Fixed"}, {"security", "Security"},
}

var fragmentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.([a-z-]+)\.md$`)
var headingLine = regexp.MustCompile(`^#{1,6}(\s|$)`)

type fragment struct {
	path    string
	section int
	body    string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "changelog:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("changelog", flag.ContinueOnError)
	fs.SetOutput(stderr)
	changelog := fs.String("changelog", "CHANGELOG.md", "published changelog path")
	dir := fs.String("dir", "changelog.d", "fragment directory")
	command := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if command == "" && fs.NArg() == 1 {
		command = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if command != "check" && command != "preview" && command != "collect" {
		return errors.New("usage: changelog <check|preview|collect> [-changelog path] [-dir path]")
	}
	fragments, err := readFragments(*dir, stderr)
	if err != nil {
		return err
	}
	if command == "check" {
		return nil
	}
	raw, err := os.ReadFile(*changelog)
	if err != nil {
		return fmt.Errorf("read changelog: %w", err)
	}
	start, end, err := unreleased(string(raw))
	if err != nil {
		return err
	}
	section := string(raw[start:end])
	newline := "\n"
	if strings.Contains(section, "\r\n") {
		newline = "\r\n"
	}
	for i := range sections {
		var bodies []string
		for _, f := range fragments {
			if f.section == i {
				bodies = append(bodies, strings.Trim(strings.ReplaceAll(f.body, "\r\n", "\n"), "\n"))
			}
		}
		if len(bodies) > 0 {
			section = appendSection(section, i, strings.ReplaceAll(strings.Join(bodies, "\n"), "\n", newline), newline)
		}
	}
	if command == "preview" {
		_, err = io.WriteString(stdout, section)
		return err
	}
	if len(fragments) == 0 {
		return nil
	}
	updated := append([]byte(nil), raw[:start]...)
	updated = append(updated, section...)
	updated = append(updated, raw[end:]...)
	info, err := os.Stat(*changelog)
	if err != nil {
		return fmt.Errorf("stat changelog: %w", err)
	}
	// Rename a sibling temporary file so an interrupted write cannot truncate the changelog.
	tmp, err := os.CreateTemp(filepath.Dir(*changelog), ".changelog-*")
	if err != nil {
		return fmt.Errorf("create changelog temporary file: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err = tmp.Chmod(info.Mode().Perm()); err == nil {
		_, err = tmp.Write(updated)
	}
	closeErr := tmp.Close()
	if err != nil {
		return fmt.Errorf("write changelog: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close changelog: %w", closeErr)
	}
	if err = os.Rename(name, *changelog); err != nil {
		return fmt.Errorf("replace changelog: %w", err)
	}
	for _, f := range fragments {
		if err := os.Remove(f.path); err != nil {
			return fmt.Errorf("remove collected fragment %s: %w", f.path, err)
		}
	}
	return nil
}

func readFragments(dir string, diagnostics io.Writer) ([]fragment, error) {
	entries, err := os.ReadDir(dir) // ReadDir guarantees filename order.
	if err != nil {
		return nil, fmt.Errorf("read fragments: %w", err)
	}
	var fragments []fragment
	invalid := false
	for _, entry := range entries {
		name := entry.Name()
		if name == "README.md" || name == ".gitkeep" {
			continue
		}
		path := filepath.Join(dir, name)
		problem := func(message string) { fmt.Fprintf(diagnostics, "%s: %s\n", path, message); invalid = true }
		match := fragmentName.FindStringSubmatch(name)
		if match == nil {
			problem("expected <lowercase-slug>.<section>.md")
			continue
		}
		index := -1
		for i, s := range sections {
			if match[1] == s.key {
				index = i
				break
			}
		}
		if index < 0 {
			problem("unknown section " + match[1])
			continue
		}
		if !entry.Type().IsRegular() {
			problem("expected a regular fragment file")
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			problem("read fragment: " + err.Error())
			continue
		}
		trimmed := strings.TrimSpace(string(body))
		if trimmed == "" {
			problem("empty body")
		} else {
			first := ""
			for _, line := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(line) != "" {
					first = strings.TrimSuffix(line, "\r")
					break
				}
			}
			if !strings.HasPrefix(first, "- ") {
				problem("first non-blank line must start with '- '")
			}
		}
		for _, line := range strings.Split(string(body), "\n") {
			if headingLine.MatchString(strings.TrimSpace(line)) {
				problem("headings are not allowed")
				break
			}
		}
		if !bytes.HasSuffix(body, []byte("\n")) {
			problem("file must end with a newline")
		}
		fragments = append(fragments, fragment{path, index, string(body)})
	}
	if invalid {
		return nil, errors.New("invalid changelog fragments")
	}
	return fragments, nil
}

// unreleased returns byte offsets, leaving the prefix and every release untouched.
func unreleased(raw string) (int, int, error) {
	start := -1
	offset := 0
	for _, line := range strings.SplitAfter(raw, "\n") {
		text := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if start < 0 && text == "## [Unreleased]" {
			start = offset
		} else if start >= 0 && strings.HasPrefix(text, "## ") {
			return start, offset, nil
		}
		offset += len(line)
	}
	if start < 0 {
		return 0, 0, errors.New("no ## [Unreleased] heading")
	}
	return start, len(raw), nil
}

func appendSection(raw string, index int, body, newline string) string {
	start, end := -1, len(raw)
	insert := len(raw)
	offset := 0
	for _, line := range strings.SplitAfter(raw, "\n") {
		text := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(text, "### ") {
			if start >= 0 {
				end = offset
				break
			}
			if text == "### "+sections[index].heading {
				start = offset + len(line)
			}
			if insert == len(raw) {
				for i, s := range sections {
					if i > index && text == "### "+s.heading {
						insert = offset
						break
					}
				}
			}
		}
		offset += len(line)
	}
	if start >= 0 {
		block := raw[start:end]
		content := strings.TrimRight(block, "\r\n")
		if content == "" {
			// Empty existing heading: entries go directly under it, then one blank line.
			return raw[:start] + body + newline + newline + raw[end:]
		}
		separator := newline
		trailing := block[len(content):]
		if trailing == "" {
			trailing = newline
		}
		return raw[:start] + content + separator + body + trailing + raw[end:]
	}
	prefix := raw[:insert]
	separator := ""
	if !strings.HasSuffix(prefix, newline+newline) {
		if strings.HasSuffix(prefix, newline) {
			separator = newline
		} else {
			separator = newline + newline
		}
	}
	return prefix + separator + "### " + sections[index].heading + newline + body + newline + newline + raw[insert:]
}
