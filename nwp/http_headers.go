// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

// NWP HTTP header and MIME constants (port of .NET NwpHttpHeaders).
// Header names are matched case-insensitively on the wire.

const (
	// Request headers
	HeaderAgent        = "X-NWP-Agent"
	HeaderBudget       = "X-NWP-Budget"
	HeaderIdent        = "X-NWP-Ident"
	HeaderCapabilities = "X-NWP-Capabilities"
	HeaderDepth        = "X-NWP-Depth"
	HeaderTrace        = "X-NWP-Trace"
	HeaderEncoding     = "X-NWP-Encoding"
	HeaderTokenizer    = "X-NWP-Tokenizer"

	// Response headers
	HeaderSchema           = "X-NWP-Schema"
	HeaderTokens           = "X-NWP-Tokens"
	HeaderTokensNative     = "X-NWP-Tokens-Native"
	HeaderTokenizerUsed    = "X-NWP-Tokenizer-Used"
	HeaderCached           = "X-NWP-Cached"
	HeaderNodeType         = "X-NWP-Node-Type"
	HeaderRequestID        = "X-NWP-Request-Id"
	HeaderReputationStatus = "X-NWP-Reputation-Status"
	HeaderBanExpires       = "X-NWP-Ban-Expires"

	// MIME types
	MimeFrame       = "application/nwp-frame"
	MimeLegacyFrame = "application/x-nps-frame"
	MimeCapsule     = "application/nwp-capsule"
	MimeError       = "application/nwp-error+json"
	MimeManifest    = "application/nwp-manifest+json"
)
