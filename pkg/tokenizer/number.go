package tokenizer

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"GoSQLX/pkg/models"
)

// numberState tracks the state of number parsing
type numberState struct {
	isFloat     bool
	dotCount    int
	hasExponent bool
	value       strings.Builder
}

// parseNumber parses a number token with support for scientific notation
func parseNumber(input []byte) (models.Token, error) {
	state := &numberState{}
	
	for i := 0; i < len(input); i++ {
		ch := input[i]
		
		switch {
		case ch == '.':
			if err := state.handleDot(); err != nil {
				return models.Token{}, err
			}
			
		case ch == 'e' || ch == 'E':
			if err := state.handleExponent(input, &i); err != nil {
				return models.Token{}, err
			}
			
		case isDigit(rune(ch)):
			state.value.WriteByte(ch)
			
		default:
			return models.Token{}, fmt.Errorf("invalid character in number: %c", ch)
		}
	}
	
	return state.finalize()
}

func (s *numberState) handleDot() error {
	if s.hasExponent {
		return fmt.Errorf("decimal point not allowed after exponent")
	}
	s.dotCount++
	if s.dotCount > 1 {
		return fmt.Errorf("multiple decimal points not allowed")
	}
	s.isFloat = true
	s.value.WriteByte('.')
	return nil
}

func (s *numberState) handleExponent(input []byte, i *int) error {
	if s.hasExponent {
		return fmt.Errorf("multiple exponents not allowed")
	}
	s.hasExponent = true
	s.isFloat = true
	s.value.WriteByte('e')
	
	// Check for optional sign after exponent
	if *i+1 < len(input) {
		next := input[*i+1]
		if next == '+' || next == '-' {
			s.value.WriteByte(next)
			*i++
		}
	}
	
	// Require at least one digit after exponent
	if *i+1 >= len(input) || !isDigit(rune(input[*i+1])) {
		return fmt.Errorf("digit required after exponent")
	}
	
	return nil
}

func (s *numberState) finalize() (models.Token, error) {
	str := s.value.String()
	
	if s.isFloat {
		val, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return models.Token{}, fmt.Errorf("invalid float format: %s", str)
		}
		if math.IsInf(val, 0) || math.IsNaN(val) {
			return models.Token{}, fmt.Errorf("float value out of range: %s", str)
		}
		// Keep the original string representation for scientific notation
		return models.Token{Type: models.TokenTypeNumber, Value: str}, nil
	}
	
	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return models.Token{}, fmt.Errorf("invalid integer format: %s", str)
	}
	// Store the validated integer value
	str = fmt.Sprintf("%d", val)
	return models.Token{Type: models.TokenTypeNumber, Value: str}, nil
}
