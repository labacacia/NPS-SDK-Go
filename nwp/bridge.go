// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

package nwp

// NodeTypeBridge is the NWM node_type wire value for Bridge Node (NPS-2 §2A.1).
const NodeTypeBridge = "bridge"

// Standard bridge_protocols wire-string constants (NPS-CR-0001 §3).
const (
	BridgeProtocolHTTP = "http"
	BridgeProtocolGRPC = "grpc"
	BridgeProtocolMCP  = "mcp"
	BridgeProtocolA2A  = "a2a"
)

// BridgeStandardProtocols is the full set of standard bridge_protocols at alpha.11.
var BridgeStandardProtocols = []string{BridgeProtocolHTTP, BridgeProtocolGRPC, BridgeProtocolMCP, BridgeProtocolA2A}

// BridgeNodeDescriptor declares which external protocols a Bridge Node bridges, in
// each direction (NPS-CR-0010).
//
//	SupportedProtocols -> Announce.bridge_protocols          (OUTBOUND: NPS -> external)
//	InboundProtocols   -> Announce.bridge_inbound_protocols  (INBOUND:  external -> NPS)
//
// An empty InboundProtocols means the node exposes no inbound surface — an outbound-only
// Bridge Node, the only kind that existed through alpha.15. A Bridge Node MUST have at
// least one of the two non-empty.
type BridgeNodeDescriptor struct {
	Nid                string
	SupportedProtocols []string
	InboundProtocols   []string
}

// BridgeTarget is the inbound parameter object for a bridge invocation.
type BridgeTarget struct {
	Protocol string                 `json:"protocol"`
	Endpoint string                 `json:"endpoint"`
	Extras   map[string]interface{} `json:"extras,omitempty"`
}
