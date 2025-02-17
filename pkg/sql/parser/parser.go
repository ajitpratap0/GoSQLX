package parser

import (
	"strconv"
	"sync"

	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/token"
)

var parserPool = sync.Pool{
	New: func() interface{} {
		return &Parser{
			tokens: make([]token.Token, 0, 64), // Pre-allocate space for 64 tokens
		}
	},
}

// Parser struct holds the state for parsing
type Parser struct {
	tokens []token.Token
	curPos int
}

// NewParser creates a new parser from the pool
func NewParser() *Parser {
	return parserPool.Get().(*Parser)
}

// Release returns the parser to the pool
func (p *Parser) Release() {
	if p != nil {
		p.tokens = p.tokens[:0] // Clear slice but keep capacity
		p.curPos = 0
		parserPool.Put(p)
	}
}

// Reset resets the parser state for reuse
func (p *Parser) Reset() {
	p.tokens = p.tokens[:0]
	p.curPos = 0
}

// Parse method to parse tokens into an AST
func (p *Parser) Parse(tokens []token.Token) (*ast.AST, error) {
	// Reset parser state
	p.Reset()

	// Copy tokens while using token pool
	p.tokens = p.tokens[:0]
	for _, t := range tokens {
		newToken := token.Get()
		newToken.Type = t.Type
		newToken.Literal = t.Literal
		p.tokens = append(p.tokens, *newToken)
	}

	tree := ast.NewAST()
	var parseErr error

	func() {
		// Ensure tokens are returned to pool even if parsing fails
		defer func() {
			for i := range p.tokens {
				if err := token.Put(&p.tokens[i]); err != nil {
					// Combine errors if both parse and pool errors occur
					if parseErr != nil {
						parseErr = fmt.Errorf("parse error: %v, pool error: %v", parseErr, err)
					} else {
						parseErr = fmt.Errorf("pool error: %v", err)
					}
				}
			}
		}()

		for !p.isAtEnd() {
			stmt, err := p.parseStatement()
			if err != nil {
				parseErr = err
				return
			}
			if stmt != nil {
				tree.Statements = append(tree.Statements, stmt)
			}
		}
	}()

	if parseErr != nil {
		return nil, parseErr
	}

	return tree, nil
}

// Helper methods
func (p *Parser) currentToken() token.Token {
	if p.isAtEnd() {
		return token.Token{Type: token.EOF}
	}
	return p.tokens[p.curPos]
}

func (p *Parser) peekToken() token.Token {
	if p.curPos+1 >= len(p.tokens) {
		return token.Token{Type: token.EOF}
	}
	return p.tokens[p.curPos+1]
}

func (p *Parser) advance() {
	if !p.isAtEnd() {
		p.curPos++
	}
}

func (p *Parser) isAtEnd() bool {
	return p.curPos >= len(p.tokens)
}

// Parsing methods
func (p *Parser) parseStatement() ast.Statement {
	tok := p.currentToken()

	switch tok.Type {
	case "SELECT":
		return p.parseSelectStatement()
	default:
		return nil
	}
}

func (p *Parser) parseSelectStatement() *ast.SelectStatement {
	stmt := &ast.SelectStatement{}

	// Skip SELECT keyword
	p.advance()

	// Parse columns
	for !p.isAtEnd() && p.currentToken().Type != "FROM" {
		expr := p.parseExpression()
		if expr != nil {
			stmt.Columns = append(stmt.Columns, expr)
		}

		if p.currentToken().Type == "," {
			p.advance()
			continue
		}
		break
	}

	// Parse FROM clause
	if p.currentToken().Type == "FROM" {
		p.advance()
		if p.currentToken().Type == "IDENT" {
			stmt.TableName = p.currentToken().Literal
			p.advance()
		}
	}

	// Parse WHERE clause
	if p.currentToken().Type == "WHERE" {
		p.advance()
		stmt.Where = p.parseExpression()
	}

	// Parse ORDER BY
	if p.currentToken().Type == "ORDER" {
		p.advance() // skip ORDER
		if p.currentToken().Type == "BY" {
			p.advance() // skip BY
			for !p.isAtEnd() {
				expr := p.parseExpression()
				if expr != nil {
					stmt.OrderBy = append(stmt.OrderBy, expr)
				}
				if p.currentToken().Type == "," {
					p.advance()
					continue
				}
				break
			}
		}
	}

	// Parse LIMIT
	if p.currentToken().Type == "LIMIT" {
		p.advance()
		if num, err := strconv.Atoi(p.currentToken().Literal); err == nil {
			stmt.Limit = &num
			p.advance()
		}
	}

	// Parse OFFSET
	if p.currentToken().Type == "OFFSET" {
		p.advance()
		if num, err := strconv.Atoi(p.currentToken().Literal); err == nil {
			stmt.Offset = &num
			p.advance()
		}
	}

	return stmt
}

func (p *Parser) parseExpression() ast.Expression {
	left := p.parseIdentifier()

	if left == nil {
		return nil
	}

	// Check if this is a binary expression
	if p.currentToken().Type == "=" || p.currentToken().Type == "<" || p.currentToken().Type == ">" {
		operator := p.currentToken().Literal
		p.advance()

		right := p.parseIdentifier()
		if right == nil {
			return left
		}

		return &ast.BinaryExpression{
			Left:     left,
			Operator: operator,
			Right:    right,
		}
	}

	return left
}

func (p *Parser) parseIdentifier() ast.Expression {
	if p.currentToken().Type == "IDENT" {
		ident := &ast.Identifier{Name: p.currentToken().Literal}
		p.advance()
		return ident
	}
	return nil
}
