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

// Visitor defines an interface for traversing the AST using the visitor pattern.
//
// The Visitor interface enables systematic traversal of the Abstract Syntax Tree
// with full control over the traversal process. The Visit method is called for
// each node encountered by Walk.
//
// Traversal Behavior:
//   - Walk calls v.Visit(node) for each node in the tree
//   - If Visit returns a non-nil visitor w, Walk recursively visits all children with w
//   - After visiting all children, Walk calls w.Visit(nil) to signal completion
//   - If Visit returns nil visitor, Walk skips the children of that node
//   - If Visit returns an error, Walk stops immediately and returns that error
//
// Return Values:
//   - w (Visitor): Visitor to use for children (nil to skip children)
//   - err (error): Error to stop traversal (nil to continue)
//
// Example - Implementing a custom visitor:
//
//	type DepthCounter struct {
//	    depth int
//	    maxDepth int
//	}
//
//	func (d *DepthCounter) Visit(node ast.Node) (ast.Visitor, error) {
//	    if node == nil {
//	        // Called after visiting all children
//	        return nil, nil
//	    }
//
//	    d.depth++
//	    if d.depth > d.maxDepth {
//	        d.maxDepth = d.depth
//	    }
//
//	    // Return new visitor with incremented depth for children
//	    return &DepthCounter{depth: d.depth, maxDepth: d.maxDepth}, nil
//	}
//
//	// Usage:
//	counter := &DepthCounter{depth: 0, maxDepth: 0}
//	ast.Walk(counter, astNode)
//	fmt.Printf("Maximum tree depth: %d\n", counter.maxDepth)
//
// Example - Stopping traversal on error:
//
//	type ErrorFinder struct{}
//
//	func (e *ErrorFinder) Visit(node ast.Node) (ast.Visitor, error) {
//	    if node == nil {
//	        return nil, nil
//	    }
//	    if _, ok := node.(*ast.SelectStatement); ok {
//	        return nil, fmt.Errorf("found SELECT statement")
//	    }
//	    return e, nil
//	}
//
// See also: Walk(), Inspect(), Inspector
type Visitor interface {
	Visit(node Node) (w Visitor, err error)
}

// Walk traverses an AST in depth-first order using the visitor pattern.
//
// Walk performs a depth-first traversal of the Abstract Syntax Tree starting
// from the given node. It uses the Visitor interface to allow custom processing
// at each node.
//
// Traversal Algorithm:
//  1. Call v.Visit(node) for the current node
//  2. If Visit returns a non-nil visitor w and no error:
//     - Recursively walk all children with visitor w
//     - Call w.Visit(nil) after all children are visited
//  3. If Visit returns nil visitor, skip children
//  4. If Visit returns an error, stop immediately and return that error
//
// Parameters:
//   - v: Visitor interface implementation to process each node
//   - node: Starting node for traversal (must not be nil)
//
// Returns:
//   - error: First error encountered during traversal, or nil
//
// Example - Finding all function calls:
//
//	type FunctionCollector struct {
//	    functions []string
//	}
//
//	func (f *FunctionCollector) Visit(node ast.Node) (ast.Visitor, error) {
//	    if node == nil {
//	        return nil, nil
//	    }
//	    if fn, ok := node.(*ast.FunctionCall); ok {
//	        f.functions = append(f.functions, fn.Name)
//	    }
//	    return f, nil  // Continue traversing
//	}
//
//	collector := &FunctionCollector{}
//	if err := ast.Walk(collector, astNode); err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Functions found: %v\n", collector.functions)
//
// Example - Validating tree structure:
//
//	type StructureValidator struct{}
//
//	func (s *StructureValidator) Visit(node ast.Node) (ast.Visitor, error) {
//	    if node == nil {
//	        return nil, nil
//	    }
//	    // Validate: SELECT statements must have at least one column
//	    if sel, ok := node.(*ast.SelectStatement); ok {
//	        if len(sel.Columns) == 0 {
//	            return nil, fmt.Errorf("SELECT statement has no columns")
//	        }
//	    }
//	    return s, nil
//	}
//
//	validator := &StructureValidator{}
//	if err := ast.Walk(validator, astNode); err != nil {
//	    fmt.Printf("Validation error: %v\n", err)
//	}
//
// See also: Inspect(), Visitor, Inspector
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

// Inspector represents a function-based AST visitor for simplified traversal.
//
// Inspector is a function type that can be used to traverse the AST without
// creating a custom visitor type. It's a convenience wrapper around the Visitor
// interface for simple use cases.
//
// The function receives each node and returns a boolean:
//   - true: Continue traversing this node's children
//   - false: Skip this node's children (prune subtree)
//
// Example - Counting specific node types:
//
//	selectCount := 0
//	inspector := ast.Inspector(func(node ast.Node) bool {
//	    if _, ok := node.(*ast.SelectStatement); ok {
//	        selectCount++
//	    }
//	    return true  // Continue traversing
//	})
//	ast.Walk(inspector, astNode)
//
// See also: Inspect() for a more convenient function form
type Inspector func(Node) bool

// Visit implements the Visitor interface for Inspector.
//
// Visit wraps the inspector function to conform to the Visitor interface.
// It calls the inspector function and returns the appropriate visitor based
// on the boolean result:
//   - true: Returns self to continue traversing children
//   - false: Returns nil to skip children
//
// This method enables Inspector to be used with Walk().
func (f Inspector) Visit(node Node) (Visitor, error) {
	if f(node) {
		return f, nil
	}
	return nil, nil
}

// Inspect traverses an AST in depth-first order using a simple function.
//
// Inspect is a convenience wrapper around Walk that allows AST traversal using
// a simple function instead of implementing the full Visitor interface. It's
// ideal for one-off traversals and simple node inspection tasks.
//
// Traversal Behavior:
//   - Calls f(node) for each node in depth-first order
//   - If f returns true, continues to children
//   - If f returns false, skips children (prunes that subtree)
//   - After visiting children, calls f(nil) to signal completion
//
// Parameters:
//   - node: Starting node for traversal (must not be nil)
//   - f: Function called for each node, returns true to continue to children
//
// Example - Finding all table references:
//
//	var tables []string
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if ref, ok := n.(*ast.TableReference); ok {
//	        if ref.Name != "" {
//	            tables = append(tables, ref.Name)
//	        }
//	    }
//	    return true  // Continue traversing
//	})
//	fmt.Printf("Tables: %v\n", tables)
//
// Example - Finding binary expressions with specific operator:
//
//	var comparisons []*ast.BinaryExpression
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if binExpr, ok := n.(*ast.BinaryExpression); ok {
//	        if binExpr.Operator == "=" {
//	            comparisons = append(comparisons, binExpr)
//	        }
//	    }
//	    return true
//	})
//
// Example - Stopping at specific node types:
//
//	// Find all columns in SELECT, but don't traverse into subqueries
//	var columns []string
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if sel, ok := n.(*ast.SelectStatement); ok {
//	        for _, col := range sel.Columns {
//	            if id, ok := col.(*ast.Identifier); ok {
//	                columns = append(columns, id.Name)
//	            }
//	        }
//	        return false  // Don't traverse into SELECT's children
//	    }
//	    return true
//	})
//
// Example - Collecting PostgreSQL JSON operators (v1.6.0):
//
//	var jsonOps []string
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if binExpr, ok := n.(*ast.BinaryExpression); ok {
//	        switch binExpr.Operator {
//	        case "->", "->>", "#>", "#>>", "@>", "<@", "?", "?|", "?&", "#-":
//	            jsonOps = append(jsonOps, binExpr.Operator)
//	        }
//	    }
//	    return true
//	})
//	fmt.Printf("JSON operators found: %v\n", jsonOps)
//
// Example - Finding window functions:
//
//	var windowFuncs []string
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if fn, ok := n.(*ast.FunctionCall); ok {
//	        if fn.Over != nil {
//	            windowFuncs = append(windowFuncs, fn.Name)
//	        }
//	    }
//	    return true
//	})
//	fmt.Printf("Window functions: %v\n", windowFuncs)
//
// See also: Walk(), Inspector, Visitor
func Inspect(node Node, f func(Node) bool) {
	_ = Walk(Inspector(f), node)
}

// VisitFunc is a function type that can be used to implement custom visitors
// without creating a new type.
type VisitFunc func(Node) (Visitor, error)

// Visit implements the Visitor interface.
func (f VisitFunc) Visit(node Node) (Visitor, error) {
	return f(node)
}
