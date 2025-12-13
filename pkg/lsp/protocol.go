/*
Package lsp implements the Language Server Protocol (LSP) server for GoSQLX.

The LSP server provides comprehensive SQL code intelligence features for IDEs and text editors,
including real-time diagnostics, formatting, completion, and navigation capabilities.

# Protocol Implementation

This file defines the LSP protocol types and structures according to the Language Server Protocol
specification (version 3.17). It provides complete type definitions for:

  - JSON-RPC 2.0 message structures (Request, Response, Notification)
  - LSP lifecycle messages (Initialize, Initialized, Shutdown, Exit)
  - Text document synchronization (didOpen, didChange, didClose, didSave)
  - Code intelligence features (Completion, Hover, Formatting, etc.)
  - Diagnostic publishing (Errors, Warnings, Information)

# Error Codes

The package defines standard JSON-RPC 2.0 error codes:
  - ParseError (-32700): Invalid JSON received
  - InvalidRequest (-32600): Invalid JSON-RPC request
  - MethodNotFound (-32601): Method not supported
  - InvalidParams (-32602): Invalid method parameters
  - InternalError (-32603): Internal server error

And LSP-specific error codes:
  - ServerNotInitialized (-32002): Server not yet initialized
  - RequestCancelled (-32800): Request cancelled by client
  - ContentModified (-32801): Content modified during operation
  - RequestFailed (-32803): Request failed

# Usage

This package is typically not used directly. Instead, use the Server type from server.go
to create and run an LSP server instance.
*/
package lsp

import "encoding/json"

// JSON-RPC 2.0 message types

// Request represents a JSON-RPC 2.0 request message.
//
// A request is a message sent from the client to the server expecting a response.
// It contains a unique ID to correlate the request with its response, a method name
// identifying the operation to perform, and optional parameters for the method.
//
// The JSONRPC field must always be "2.0" per the JSON-RPC 2.0 specification.
//
// Example request:
//
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "method": "textDocument/hover",
//	  "params": { "textDocument": { "uri": "file:///query.sql" }, "position": { "line": 0, "character": 5 } }
//	}
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response message.
//
// A response is sent from the server back to the client in reply to a request.
// It contains the same ID as the request to correlate them. Either Result or
// Error will be set, but never both.
//
// The JSONRPC field must always be "2.0" per the JSON-RPC 2.0 specification.
//
// Example successful response:
//
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "result": { "contents": { "kind": "markdown", "value": "**SELECT** - Retrieves data..." } }
//	}
//
// Example error response:
//
//	{
//	  "jsonrpc": "2.0",
//	  "id": 1,
//	  "error": { "code": -32601, "message": "Method not found" }
//	}
type Response struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      interface{}    `json:"id,omitempty"`
	Result  interface{}    `json:"result,omitempty"`
	Error   *ResponseError `json:"error,omitempty"`
}

// ResponseError represents a JSON-RPC 2.0 error.
//
// This type carries error information when a request fails. The Code field
// contains a numeric error code (see error code constants), Message provides
// a human-readable description, and Data optionally contains additional context.
//
// Standard error codes are defined as package constants (ParseError, InvalidRequest, etc.).
type ResponseError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Notification represents a JSON-RPC 2.0 notification (request without ID).
//
// A notification is a special type of request that does not expect a response.
// It has no ID field, and the server will not send a response. Notifications
// are used for events that the client sends to the server without needing
// acknowledgment, such as document change notifications.
//
// Example notification:
//
//	{
//	  "jsonrpc": "2.0",
//	  "method": "textDocument/didChange",
//	  "params": { "textDocument": { "uri": "file:///query.sql", "version": 2 }, "contentChanges": [...] }
//	}
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error codes
const (
	// JSON-RPC standard error codes
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603

	// LSP-specific error codes
	ServerNotInitialized = -32002
	UnknownErrorCode     = -32001
	RequestCancelled     = -32800
	ContentModified      = -32801
	ServerCancelled      = -32802
	RequestFailed        = -32803
)

// LSP-specific types

// InitializeParams contains initialization options
type InitializeParams struct {
	ProcessID             int                `json:"processId"`
	RootURI               string             `json:"rootUri"`
	RootPath              string             `json:"rootPath,omitempty"`
	Capabilities          ClientCapabilities `json:"capabilities"`
	InitializationOptions interface{}        `json:"initializationOptions,omitempty"`
}

// ClientCapabilities describes the client's capabilities
type ClientCapabilities struct {
	TextDocument TextDocumentClientCapabilities `json:"textDocument,omitempty"`
}

// TextDocumentClientCapabilities describes text document capabilities
type TextDocumentClientCapabilities struct {
	Synchronization    *TextDocumentSyncClientCapabilities   `json:"synchronization,omitempty"`
	Completion         *CompletionClientCapabilities         `json:"completion,omitempty"`
	Hover              *HoverClientCapabilities              `json:"hover,omitempty"`
	PublishDiagnostics *PublishDiagnosticsClientCapabilities `json:"publishDiagnostics,omitempty"`
}

// TextDocumentSyncClientCapabilities describes sync capabilities
type TextDocumentSyncClientCapabilities struct {
	DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	WillSave            bool `json:"willSave,omitempty"`
	WillSaveWaitUntil   bool `json:"willSaveWaitUntil,omitempty"`
	DidSave             bool `json:"didSave,omitempty"`
}

// CompletionClientCapabilities describes completion capabilities
type CompletionClientCapabilities struct {
	DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
	CompletionItem      *struct {
		SnippetSupport bool `json:"snippetSupport,omitempty"`
	} `json:"completionItem,omitempty"`
}

// HoverClientCapabilities describes hover capabilities
type HoverClientCapabilities struct {
	DynamicRegistration bool     `json:"dynamicRegistration,omitempty"`
	ContentFormat       []string `json:"contentFormat,omitempty"`
}

// PublishDiagnosticsClientCapabilities describes diagnostics capabilities
type PublishDiagnosticsClientCapabilities struct {
	RelatedInformation bool `json:"relatedInformation,omitempty"`
}

// InitializeResult is the response to initialize
type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
	ServerInfo   *ServerInfo        `json:"serverInfo,omitempty"`
}

// ServerInfo provides information about the server
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// ServerCapabilities describes what the server can do
type ServerCapabilities struct {
	TextDocumentSync           *TextDocumentSyncOptions `json:"textDocumentSyncOptions,omitempty"`
	CompletionProvider         *CompletionOptions       `json:"completionProvider,omitempty"`
	HoverProvider              bool                     `json:"hoverProvider,omitempty"`
	DocumentFormattingProvider bool                     `json:"documentFormattingProvider,omitempty"`
	DocumentSymbolProvider     bool                     `json:"documentSymbolProvider,omitempty"`
	SignatureHelpProvider      *SignatureHelpOptions    `json:"signatureHelpProvider,omitempty"`
	CodeActionProvider         interface{}              `json:"codeActionProvider,omitempty"` // bool or CodeActionOptions
}

// TextDocumentSyncOptions describes how documents are synced
type TextDocumentSyncOptions struct {
	OpenClose bool                 `json:"openClose,omitempty"`
	Change    TextDocumentSyncKind `json:"change,omitempty"`
	Save      *SaveOptions         `json:"save,omitempty"`
}

// TextDocumentSyncKind defines how the client syncs document changes
type TextDocumentSyncKind int

const (
	// SyncNone means documents should not be synced at all
	SyncNone TextDocumentSyncKind = 0
	// SyncFull means documents are synced by sending the full content
	SyncFull TextDocumentSyncKind = 1
	// SyncIncremental means documents are synced by sending incremental updates
	SyncIncremental TextDocumentSyncKind = 2
)

// SaveOptions describes save options
type SaveOptions struct {
	IncludeText bool `json:"includeText,omitempty"`
}

// CompletionOptions describes completion options
type CompletionOptions struct {
	TriggerCharacters []string `json:"triggerCharacters,omitempty"`
	ResolveProvider   bool     `json:"resolveProvider,omitempty"`
}

// TextDocumentIdentifier identifies a document
type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

// VersionedTextDocumentIdentifier identifies a specific version of a document
type VersionedTextDocumentIdentifier struct {
	TextDocumentIdentifier
	Version int `json:"version"`
}

// TextDocumentItem represents a document
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

// DidOpenTextDocumentParams is sent when a document is opened
type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// DidChangeTextDocumentParams is sent when a document changes
type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier  `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent `json:"contentChanges"`
}

// TextDocumentContentChangeEvent describes a content change
type TextDocumentContentChangeEvent struct {
	Range       *Range `json:"range,omitempty"`
	RangeLength int    `json:"rangeLength,omitempty"`
	Text        string `json:"text"`
}

// DidCloseTextDocumentParams is sent when a document is closed
type DidCloseTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// DidSaveTextDocumentParams is sent when a document is saved
type DidSaveTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Text         string                 `json:"text,omitempty"`
}

// Position in a text document
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range in a text document
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Location represents a location in a document
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// Diagnostic represents a diagnostic (error, warning, etc.)
type Diagnostic struct {
	Range              Range                          `json:"range"`
	Severity           DiagnosticSeverity             `json:"severity,omitempty"`
	Code               interface{}                    `json:"code,omitempty"`
	Source             string                         `json:"source,omitempty"`
	Message            string                         `json:"message"`
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
}

// DiagnosticSeverity represents the severity of a diagnostic
type DiagnosticSeverity int

const (
	// SeverityError reports an error
	SeverityError DiagnosticSeverity = 1
	// SeverityWarning reports a warning
	SeverityWarning DiagnosticSeverity = 2
	// SeverityInformation reports information
	SeverityInformation DiagnosticSeverity = 3
	// SeverityHint reports a hint
	SeverityHint DiagnosticSeverity = 4
)

// DiagnosticRelatedInformation provides additional context
type DiagnosticRelatedInformation struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

// PublishDiagnosticsParams is sent to publish diagnostics
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     int          `json:"version,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// TextDocumentPositionParams identifies a position in a document
type TextDocumentPositionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Position     Position               `json:"position"`
}

// Hover represents hover information
type Hover struct {
	Contents MarkupContent `json:"contents"`
	Range    *Range        `json:"range,omitempty"`
}

// MarkupContent represents markup content
type MarkupContent struct {
	Kind  MarkupKind `json:"kind"`
	Value string     `json:"value"`
}

// MarkupKind describes the markup type
type MarkupKind string

const (
	// PlainText is plain text
	PlainText MarkupKind = "plaintext"
	// Markdown is markdown
	Markdown MarkupKind = "markdown"
)

// CompletionParams describes completion request parameters
type CompletionParams struct {
	TextDocumentPositionParams
	Context *CompletionContext `json:"context,omitempty"`
}

// CompletionContext provides additional information about the context
type CompletionContext struct {
	TriggerKind      CompletionTriggerKind `json:"triggerKind"`
	TriggerCharacter string                `json:"triggerCharacter,omitempty"`
}

// CompletionTriggerKind describes how completion was triggered
type CompletionTriggerKind int

const (
	// Invoked means completion was invoked explicitly
	Invoked CompletionTriggerKind = 1
	// TriggerCharacter means completion was triggered by a character
	TriggerCharacter CompletionTriggerKind = 2
	// TriggerForIncompleteCompletions means re-triggered for incomplete completions
	TriggerForIncompleteCompletions CompletionTriggerKind = 3
)

// CompletionList represents a list of completion items
type CompletionList struct {
	IsIncomplete bool             `json:"isIncomplete"`
	Items        []CompletionItem `json:"items"`
}

// CompletionItem represents a completion suggestion
type CompletionItem struct {
	Label            string             `json:"label"`
	Kind             CompletionItemKind `json:"kind,omitempty"`
	Detail           string             `json:"detail,omitempty"`
	Documentation    interface{}        `json:"documentation,omitempty"`
	InsertText       string             `json:"insertText,omitempty"`
	InsertTextFormat InsertTextFormat   `json:"insertTextFormat,omitempty"`
}

// CompletionItemKind defines the kind of completion item
type CompletionItemKind int

const (
	TextCompletion     CompletionItemKind = 1
	MethodCompletion   CompletionItemKind = 2
	FunctionCompletion CompletionItemKind = 3
	KeywordCompletion  CompletionItemKind = 14
	SnippetCompletion  CompletionItemKind = 15
)

// InsertTextFormat defines the format of the insert text
type InsertTextFormat int

const (
	PlainTextFormat InsertTextFormat = 1
	SnippetFormat   InsertTextFormat = 2
)

// DocumentFormattingParams describes formatting request parameters
type DocumentFormattingParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Options      FormattingOptions      `json:"options"`
}

// FormattingOptions describes formatting options
type FormattingOptions struct {
	TabSize                int  `json:"tabSize"`
	InsertSpaces           bool `json:"insertSpaces"`
	TrimTrailingWhitespace bool `json:"trimTrailingWhitespace,omitempty"`
	InsertFinalNewline     bool `json:"insertFinalNewline,omitempty"`
	TrimFinalNewlines      bool `json:"trimFinalNewlines,omitempty"`
}

// TextEdit represents a text edit
type TextEdit struct {
	Range   Range  `json:"range"`
	NewText string `json:"newText"`
}

// ShutdownResult is the result of a shutdown request
type ShutdownResult struct{}

// ShowMessageParams is used to show a message to the user
type ShowMessageParams struct {
	Type    MessageType `json:"type"`
	Message string      `json:"message"`
}

// MessageType represents the type of message to show
type MessageType int

const (
	// MessageError is an error message
	MessageError MessageType = 1
	// MessageWarning is a warning message
	MessageWarning MessageType = 2
	// MessageInfo is an info message
	MessageInfo MessageType = 3
	// MessageLog is a log message
	MessageLog MessageType = 4
)

// DocumentSymbol represents a symbol in a document (hierarchical)
type DocumentSymbol struct {
	Name           string           `json:"name"`
	Detail         string           `json:"detail,omitempty"`
	Kind           SymbolKind       `json:"kind"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

// SymbolInformation represents a symbol (flat list)
type SymbolInformation struct {
	Name          string     `json:"name"`
	Kind          SymbolKind `json:"kind"`
	Location      Location   `json:"location"`
	ContainerName string     `json:"containerName,omitempty"`
}

// SymbolKind represents the kind of symbol
type SymbolKind int

const (
	SymbolFile        SymbolKind = 1
	SymbolModule      SymbolKind = 2
	SymbolNamespace   SymbolKind = 3
	SymbolPackage     SymbolKind = 4
	SymbolClass       SymbolKind = 5
	SymbolMethod      SymbolKind = 6
	SymbolProperty    SymbolKind = 7
	SymbolField       SymbolKind = 8
	SymbolConstructor SymbolKind = 9
	SymbolEnum        SymbolKind = 10
	SymbolInterface   SymbolKind = 11
	SymbolFunction    SymbolKind = 12
	SymbolVariable    SymbolKind = 13
	SymbolConstant    SymbolKind = 14
	SymbolString      SymbolKind = 15
	SymbolNumber      SymbolKind = 16
	SymbolBoolean     SymbolKind = 17
	SymbolArray       SymbolKind = 18
	SymbolObject      SymbolKind = 19
	SymbolKey         SymbolKind = 20
	SymbolNull        SymbolKind = 21
	SymbolEnumMember  SymbolKind = 22
	SymbolStruct      SymbolKind = 23
	SymbolEvent       SymbolKind = 24
	SymbolOperator    SymbolKind = 25
	SymbolTypeParam   SymbolKind = 26
)

// DocumentSymbolParams is the parameters for textDocument/documentSymbol
type DocumentSymbolParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// SignatureHelp represents signature help information
type SignatureHelp struct {
	Signatures      []SignatureInformation `json:"signatures"`
	ActiveSignature int                    `json:"activeSignature,omitempty"`
	ActiveParameter int                    `json:"activeParameter,omitempty"`
}

// SignatureInformation represents a function signature
type SignatureInformation struct {
	Label         string                 `json:"label"`
	Documentation interface{}            `json:"documentation,omitempty"`
	Parameters    []ParameterInformation `json:"parameters,omitempty"`
}

// ParameterInformation represents a parameter of a function signature
type ParameterInformation struct {
	Label         interface{} `json:"label"` // string or [int, int]
	Documentation interface{} `json:"documentation,omitempty"`
}

// SignatureHelpOptions describes signature help options
type SignatureHelpOptions struct {
	TriggerCharacters   []string `json:"triggerCharacters,omitempty"`
	RetriggerCharacters []string `json:"retriggerCharacters,omitempty"`
}

// CodeActionParams is the parameters for textDocument/codeAction
type CodeActionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Range        Range                  `json:"range"`
	Context      CodeActionContext      `json:"context"`
}

// CodeActionContext contains additional diagnostic information
type CodeActionContext struct {
	Diagnostics []Diagnostic     `json:"diagnostics"`
	Only        []CodeActionKind `json:"only,omitempty"`
}

// CodeActionKind represents the kind of code action
type CodeActionKind string

const (
	CodeActionQuickFix       CodeActionKind = "quickfix"
	CodeActionRefactor       CodeActionKind = "refactor"
	CodeActionSource         CodeActionKind = "source"
	CodeActionSourceOrganize CodeActionKind = "source.organizeImports"
)

// CodeAction represents a code action
type CodeAction struct {
	Title       string         `json:"title"`
	Kind        CodeActionKind `json:"kind,omitempty"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
	IsPreferred bool           `json:"isPreferred,omitempty"`
	Edit        *WorkspaceEdit `json:"edit,omitempty"`
	Command     *Command       `json:"command,omitempty"`
}

// WorkspaceEdit represents changes to be applied to a workspace
type WorkspaceEdit struct {
	Changes         map[string][]TextEdit `json:"changes,omitempty"`
	DocumentChanges []TextDocumentEdit    `json:"documentChanges,omitempty"`
}

// TextDocumentEdit represents an edit to a single document
type TextDocumentEdit struct {
	TextDocument VersionedTextDocumentIdentifier `json:"textDocument"`
	Edits        []TextEdit                      `json:"edits"`
}

// Command represents a command to be executed
type Command struct {
	Title     string        `json:"title"`
	Command   string        `json:"command"`
	Arguments []interface{} `json:"arguments,omitempty"`
}

// CodeActionOptions describes code action options
type CodeActionOptions struct {
	CodeActionKinds []CodeActionKind `json:"codeActionKinds,omitempty"`
}
