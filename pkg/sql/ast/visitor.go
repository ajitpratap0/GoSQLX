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

// Visitor defines an interface for traversing the AST.
// The Visit method is called for each node encountered by Walk.
// If the result visitor w is not nil, Walk visits each of the children
// of node with the visitor w, followed by a call of w.Visit(nil).
type Visitor interface {
	Visit(node Node) (w Visitor, err error)
}

// Walk traverses an AST in depth-first order: It starts by calling
// v.Visit(node); node must not be nil. If the visitor w returned by
// v.Visit(node) is not nil, Walk is invoked recursively with visitor
// w for each of the non-nil children of node, followed by a call of
// w.Visit(nil).
func Walk(v Visitor, node Node) error {
	if node == nil {
		return nil
	}

	visitor, err := v.Visit(node)
	if err != nil {
		return err
	}

	if visitor == nil {
		return nil
	}

	for _, child := range node.Children() {
		if err := Walk(visitor, child); err != nil {
			return err
		}
	}

	_, err = visitor.Visit(nil)
	return err
}

// Inspector represents an AST visitor that can be used to traverse an AST
// and invoke a custom function for each node.
type Inspector func(Node) bool

// Visit implements the Visitor interface.
func (f Inspector) Visit(node Node) (Visitor, error) {
	if f(node) {
		return f, nil
	}
	return nil, nil
}

// Inspect traverses an AST in depth-first order: It starts by calling
// f(node); node must not be nil. If f returns true, Inspect invokes f
// recursively for each of the non-nil children of node, followed by a
// call of f(nil).
func Inspect(node Node, f func(Node) bool) {
	Walk(Inspector(f), node)
}

// VisitFunc is a function type that can be used to implement custom visitors
// without creating a new type.
type VisitFunc func(Node) (Visitor, error)

// Visit implements the Visitor interface.
func (f VisitFunc) Visit(node Node) (Visitor, error) {
	return f(node)
}
