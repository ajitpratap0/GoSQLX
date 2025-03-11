package models

// TokenizerError represents an error during tokenization
type TokenizerError struct {
	Message  string
	Location Location
}

func (e TokenizerError) Error() string {
	return e.Message
}
