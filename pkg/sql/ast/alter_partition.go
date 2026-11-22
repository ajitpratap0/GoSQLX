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

package ast

// partitionActionKeywords are the AlterPartitioning keyword phrases the
// renderer writes.
var partitionActionKeywords = []string{
	"ADD PARTITION", "DROP PARTITION", "TRUNCATE PARTITION", "REORGANIZE PARTITION",
	"COALESCE PARTITION", "EXCHANGE PARTITION", "ANALYZE PARTITION", "CHECK PARTITION",
	"OPTIMIZE PARTITION", "REBUILD PARTITION", "REPAIR PARTITION", "DISCARD PARTITION",
	"IMPORT PARTITION", "REMOVE PARTITIONING", "UPGRADE PARTITIONING",
}

func (w alterWriter) writePartitionAction(op *AlterTableOperation) {
	if op.Keyword == "PARTITION BY" {
		if op.Partitioning != nil {
			buf := getBuf()
			defer putBuf(buf)
			writePartitionBy(buf, op.Partitioning, w.st)
			w.str(buf.String()[1:])
		}
		writePartitionDefinitions(w.buf, op.PartitionDefinitions, w.st)
		return
	}
	kw := keywordOneOf(op.Keyword, partitionActionKeywords)
	if kw == "" {
		return
	}
	w.kwStr(kw)
	switch {
	case op.IfNotExists:
		w.str(" ")
		w.kwStr("IF NOT EXISTS")
	case op.IfExists:
		w.str(" ")
		w.kwStr("IF EXISTS")
	}
	if op.PartitionAll {
		w.str(" ")
		w.kwStr("ALL")
	}
	for i, name := range op.PartitionNames {
		if i == 0 {
			w.str(" ")
		} else {
			w.str(", ")
		}
		w.str(w.identName(name))
	}
	if op.PartitionCount != nil {
		w.str(" ")
		if kw == "ADD PARTITION" {
			w.kwStr("PARTITIONS")
			w.str(" ")
		}
		w.expr(op.PartitionCount)
	}
	if kw == "REORGANIZE PARTITION" && len(op.PartitionDefinitions) > 0 {
		w.str(" ")
		w.kwStr("INTO")
	}
	writePartitionDefinitions(w.buf, op.PartitionDefinitions, w.st)
	if kw == "EXCHANGE PARTITION" {
		w.str(" ")
		w.kwStr("WITH TABLE")
		w.str(" ")
		w.str(QuoteQualifiedNameWith(op.ExchangeTable.Name, w.st.nq(op.ExchangeTable.Quote)))
		if v := keywordOneOf(op.Validation, []string{"WITH", "WITHOUT"}); v != "" {
			w.str(" ")
			w.kwStr(v + " VALIDATION")
		}
	}
	if kw == "DISCARD PARTITION" || kw == "IMPORT PARTITION" {
		w.str(" ")
		w.kwStr("TABLESPACE")
	}
}

func releaseAlterPartitionFields(op *AlterTableOperation, mode releaseMode) {
	if op.Partitioning != nil {
		for _, expr := range op.Partitioning.Boundary {
			releaseExpression(expr, mode)
		}
		releasePartitionByExtras(op.Partitioning, mode)
		*op.Partitioning = PartitionBy{}
		op.Partitioning = nil
	}
	for i := range op.PartitionDefinitions {
		def := &op.PartitionDefinitions[i]
		for _, expr := range def.Values {
			releaseExpression(expr, mode)
		}
		for _, expr := range def.InValues {
			releaseExpression(expr, mode)
		}
		releaseExpression(def.LessThan, mode)
		releaseExpression(def.From, mode)
		releaseExpression(def.To, mode)
		*def = PartitionDefinition{}
	}
	op.PartitionDefinitions = nil
	op.PartitionNames = nil
	releaseExpression(op.PartitionCount, mode)
	op.PartitionCount = nil
}
