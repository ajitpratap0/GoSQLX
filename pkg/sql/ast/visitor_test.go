// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ast

import (
	"testing"
)

type nodeCounter struct {
	count int
}

func (v *nodeCounter) Visit(node Node) (Visitor, error) {
	if node != nil {
		v.count++
	}
	return v, nil
}

func TestVisitor(t *testing.T) {
	// Create a simple AST
	ast := &AST{
		Statements: []Statement{
			&SelectStatement{
				Columns: []Expression{
					&Identifier{Name: "id"},
					&Identifier{Name: "name"},
				},
				TableName: "users",
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "id"},
					Operator: "=",
					Right:    &Identifier{Name: "1"},
				},
			},
		},
	}

	counter := &nodeCounter{}
	err := Walk(counter, ast)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Count expected nodes:
	// 1. AST
	// 2. SelectStatement
	// 3-4. Two column Identifiers
	// 5. BinaryExpression
	// 6-7. Left and right Identifiers in BinaryExpression
	expectedCount := 7
	if counter.count != expectedCount {
		t.Errorf("expected %d nodes, got %d", expectedCount, counter.count)
	}
}

type nodeCollector struct {
	nodes []Node
}

func (v *nodeCollector) Visit(node Node) (Visitor, error) {
	if node != nil {
		v.nodes = append(v.nodes, node)
	}
	return v, nil
}

func TestInspector(t *testing.T) {
	// Create a simple AST
	ast := &AST{
		Statements: []Statement{
			&SelectStatement{
				Columns: []Expression{
					&Identifier{Name: "id"},
				},
				TableName: "users",
			},
		},
	}

	var identifiers []*Identifier
	Inspect(ast, func(n Node) bool {
		if id, ok := n.(*Identifier); ok {
			identifiers = append(identifiers, id)
		}
		return true
	})

	if len(identifiers) != 1 {
		t.Errorf("expected 1 identifier, got %d", len(identifiers))
	}
	if identifiers[0].Name != "id" {
		t.Errorf("expected identifier name 'id', got '%s'", identifiers[0].Name)
	}
}

func TestVisitFunc(t *testing.T) {
	ast := &AST{
		Statements: []Statement{
			&SelectStatement{
				Columns: []Expression{
					&Identifier{Name: "id"},
				},
				TableName: "users",
			},
		},
	}

	var count int
	visitor := VisitFunc(func(n Node) (Visitor, error) {
		if n != nil {
			count++
		}
		return nil, nil // Don't visit children
	})

	err := Walk(visitor, ast)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if count != 1 { // Should only visit root node since we return nil
		t.Errorf("expected count of 1, got %d", count)
	}
}
