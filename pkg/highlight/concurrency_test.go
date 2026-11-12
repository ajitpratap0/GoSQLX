// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package highlight_test

import (
	"math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestSpansConcurrentMatchesSerial(t *testing.T) {
	corpus, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	type document struct {
		sql     string
		dialect keywords.SQLDialect
		want    []highlight.Span
	}
	docs := make([]document, 0, 42)
	for _, dialect := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLServer, keywords.DialectSQLite} {
		stmts := corpus.ByDialect(string(dialect))
		if len(stmts) < 10 {
			t.Fatalf("dialect %s has %d corpus statements, want at least 10", dialect, len(stmts))
		}
		for _, stmt := range stmts[:10] {
			docs = append(docs, document{sql: stmt.SQL, dialect: dialect})
		}
	}
	script := benchcorpus.Script(corpus.ByDialect(string(keywords.DialectPostgreSQL)), 30*1024)
	docs = append(docs, document{sql: script.SQL, dialect: keywords.DialectPostgreSQL}, document{sql: "SELECT a FROM t WHERE b = 'unterminated", dialect: keywords.DialectPostgreSQL})
	for i := range docs {
		docs[i].want = highlight.Spans(docs[i].sql, highlight.WithDialect(docs[i].dialect))
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(worker + 1)))
			order := rng.Perm(len(docs))
			for iteration := 0; iteration < 50; iteration++ {
				rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
				for _, index := range order {
					doc := docs[index]
					got := highlight.Spans(doc.sql, highlight.WithDialect(doc.dialect))
					if !reflect.DeepEqual(got, doc.want) {
						t.Errorf("worker %d iteration %d document %d (%s): got %v, want %v", worker, iteration, index, doc.dialect, got, doc.want)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}
