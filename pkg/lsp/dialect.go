// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lsp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Dialect routing
//
// The configured dialect (Handler.dialect) drives every feature that
// tokenizes or parses: diagnostics, formatting, document symbols and
// semantic tokens. Completion and hover additionally offer the dialect's
// own keywords.
//
// DialectGeneric (the default when the client sends no dialect) keeps the
// exact pipeline the server used before it became dialect-aware: the
// dialect-less gosqlx.Parse / ParseWithRecovery / Format entry points, which
// tokenize with the tokenizer pool's default (PostgreSQL keyword rules) and
// parse with no parser dialect. Passing "generic" explicitly to the
// dialect-aware APIs is NOT equivalent: for example ILIKE parses with the
// default pipeline but is rejected by ParseWithDialect(sql, "generic"). Only
// an explicitly chosen non-generic dialect switches to the dialect-aware
// APIs, so existing users see no change.

// usesDefaultPipeline reports whether d selects the server's original,
// dialect-less parsing pipeline.
func usesDefaultPipeline(d keywords.SQLDialect) bool {
	return d == "" || d == keywords.DialectGeneric || d == keywords.DialectUnknown
}

// parseWithRecoveryForDialect is gosqlx.ParseWithRecovery with the tokenizer
// and parser configured for d. Errors are wrapped with the same gosqlx
// sentinels so diagnostics look the same for every dialect.
func parseWithRecoveryForDialect(sql string, d keywords.SQLDialect) ([]ast.Statement, []error) {
	if usesDefaultPipeline(d) {
		return gosqlx.ParseWithRecovery(sql)
	}

	// PutTokenizer restores the pool's default dialect.
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(d)

	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return nil, []error{fmt.Errorf("%w: %w", gosqlx.ErrTokenize, err)}
	}

	// PutParser resets the parser's dialect.
	p := parser.GetParser()
	defer parser.PutParser(p)
	p.ApplyOptions(parser.WithDialect(string(d)))

	stmts, recoveryErrs := p.ParseWithRecoveryFromModelTokens(tokens)
	if len(recoveryErrs) > 0 {
		wrapped := make([]error, len(recoveryErrs))
		for i, e := range recoveryErrs {
			wrapped[i] = fmt.Errorf("%w: %w", gosqlx.ErrSyntax, e)
		}
		return stmts, wrapped
	}
	return stmts, nil
}

// parseForDialect parses sql with the dialect-aware API for d, or with
// gosqlx.Parse for the default pipeline.
func parseForDialect(sql string, d keywords.SQLDialect) (*ast.AST, error) {
	if usesDefaultPipeline(d) {
		return gosqlx.Parse(sql)
	}
	return gosqlx.ParseWithDialect(sql, d)
}

// formatForDialect formats sql like gosqlx.Format, but parses it with the
// dialect-aware API for d and renders dialect-specific constructs for d.
// Comments and optimizer hints are preserved. opts.AddSemicolon is honoured.
func formatForDialect(sql string, opts gosqlx.FormatOptions, d keywords.SQLDialect) (string, error) {
	if usesDefaultPipeline(d) {
		return gosqlx.Format(sql, opts)
	}
	return gosqlx.FormatWithDialect(sql, opts, d)
}

// dialectDisplayNames are the human-readable dialect names used in
// completion details and hover text.
var dialectDisplayNames = map[keywords.SQLDialect]string{
	keywords.DialectPostgreSQL: "PostgreSQL",
	keywords.DialectMySQL:      "MySQL",
	keywords.DialectMariaDB:    "MariaDB",
	keywords.DialectSQLServer:  "SQL Server",
	keywords.DialectOracle:     "Oracle",
	keywords.DialectSQLite:     "SQLite",
	keywords.DialectSnowflake:  "Snowflake",
	keywords.DialectBigQuery:   "BigQuery",
	keywords.DialectRedshift:   "Redshift",
	keywords.DialectClickHouse: "ClickHouse",
}

// dialectDisplayName returns the human-readable name of d.
func dialectDisplayName(d keywords.SQLDialect) string {
	if name, ok := dialectDisplayNames[d]; ok {
		return name
	}
	return string(d)
}

// dialectKeywordCompletions holds, per dialect, a completion item for each
// dialect-specific keyword (keywords.DialectKeywords) that the generic
// sqlKeywords list does not already offer. Built once; read-only afterwards.
var dialectKeywordCompletions = buildDialectKeywordCompletions()

func buildDialectKeywordCompletions() map[keywords.SQLDialect][]CompletionItem {
	base := make(map[string]bool, len(sqlKeywords))
	for _, kw := range sqlKeywords {
		base[strings.ToUpper(kw.Label)] = true
	}
	out := make(map[keywords.SQLDialect][]CompletionItem)
	for _, d := range keywords.AllDialects() {
		seen := make(map[string]bool)
		var items []CompletionItem
		for _, kw := range keywords.DialectKeywords(d) {
			word := strings.ToUpper(kw.Word)
			if word == "" || base[word] || seen[word] {
				continue
			}
			seen[word] = true
			items = append(items, CompletionItem{
				Label:  word,
				Kind:   KeywordCompletion,
				Detail: dialectDisplayName(d) + " keyword",
			})
		}
		if len(items) > 0 {
			out[d] = items
		}
	}
	return out
}

// isDialectKeyword reports whether upperWord is one of d's dialect-specific
// keywords offered by completion.
func isDialectKeyword(upperWord string, d keywords.SQLDialect) bool {
	for _, item := range dialectKeywordCompletions[d] {
		if item.Label == upperWord {
			return true
		}
	}
	return false
}

// dialectKeywordHover returns hover markdown for a dialect-specific keyword
// of d that has no entry in the generic keyword documentation, or "".
func dialectKeywordHover(upperWord string, d keywords.SQLDialect) string {
	if usesDefaultPipeline(d) || !isDialectKeyword(upperWord, d) {
		return ""
	}
	return fmt.Sprintf("**%s** - %s-specific keyword.", upperWord, dialectDisplayName(d))
}

// dialectFromSettings extracts the dialect from workspace/didChangeConfiguration
// settings shaped {"gosqlx": {"dialect": "mysql"}}. ok is false when the
// settings carry no gosqlx.dialect entry at all (for example the null
// settings vscode-languageclient sends without a configurationSection), in
// which case the current dialect is kept. A present but non-string, empty or
// unrecognised value is validated exactly like initializationOptions and
// falls back to DialectGeneric, so a live change and a server restart with
// the same setting always agree.
func dialectFromSettings(settings interface{}) (d keywords.SQLDialect, ok bool) {
	root, isMap := settings.(map[string]interface{})
	if !isMap {
		return "", false
	}
	section, isMap := root["gosqlx"].(map[string]interface{})
	if !isMap {
		return "", false
	}
	if _, present := section["dialect"]; !present {
		return "", false
	}
	return dialectFromInitOptions(section), true
}

// handleDidChangeConfiguration applies a gosqlx.dialect change without a
// server restart. When the dialect actually changes, diagnostics of every
// open document are re-published under the new dialect and, if the client
// advertised workspace.semanticTokens.refreshSupport, the client is asked to
// re-request semantic tokens. Hover, completion, formatting and document
// symbols read the dialect per request and need no refresh.
func (h *Handler) handleDidChangeConfiguration(params json.RawMessage) {
	var p DidChangeConfigurationParams
	if err := json.Unmarshal(params, &p); err != nil {
		h.server.Logger().Printf("workspace/didChangeConfiguration: failed to parse params: %v (raw: %s)", err, truncateForLog(params))
		h.sendParseError("didChangeConfiguration", err)
		return
	}

	d, ok := dialectFromSettings(p.Settings)
	if !ok {
		h.server.Logger().Printf("workspace/didChangeConfiguration: no gosqlx.dialect setting; keeping %s", h.currentDialect())
		return
	}
	if !h.setDialect(d) {
		return
	}

	h.revalidateOpenDocuments()

	if h.semanticRefresh.Load() {
		h.server.sendRequest("workspace/semanticTokens/refresh", nil)
	}
}

// revalidateOpenDocuments re-publishes diagnostics for every open document
// that is within the size limit, using the current dialect.
//
// Each document is re-fetched just before it is validated, so a document
// closed or edited since the snapshot is skipped or validated at its current
// version rather than publishing diagnostics for stale content. A pending
// debounced didChange validation is cancelled: it would only re-validate the
// same content. One that is already running and parsed under the previous
// dialect is dropped by validateDocument's dialect check.
func (h *Handler) revalidateOpenDocuments() {
	docs := h.server.Documents()
	for _, snap := range docs.snapshots() {
		h.debounceMu.Lock()
		if t, ok := h.debounceTimers[snap.URI]; ok {
			t.Stop()
			delete(h.debounceTimers, snap.URI)
		}
		h.debounceMu.Unlock()

		doc, ok := docs.Get(snap.URI)
		if !ok || len(doc.Content) > h.server.MaxDocumentSizeBytes() {
			continue
		}
		h.validateDocument(doc.URI, doc.Content, doc.Version)
	}
}
