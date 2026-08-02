package nwp

import "testing"

func TestBridgeConstants(t *testing.T) {
	if NodeTypeBridge != "bridge" { t.Error("NodeTypeBridge") }
	if BridgeProtocolHTTP != "http" { t.Error("HTTP") }
	if BridgeProtocolGRPC != "grpc" { t.Error("GRPC") }
	if BridgeProtocolMCP  != "mcp"  { t.Error("MCP") }
	if BridgeProtocolA2A  != "a2a"  { t.Error("A2A") }
	if len(BridgeStandardProtocols) != 4 { t.Error("len") }
}

func TestBridgeNodeDescriptor(t *testing.T) {
	d := BridgeNodeDescriptor{Nid: "urn:nps:node:ex.com:b", SupportedProtocols: []string{"http", "grpc"}}
	if d.Nid == "" || len(d.SupportedProtocols) != 2 { t.Error("fields") }
}

func TestBridgeTarget(t *testing.T) {
	bt := BridgeTarget{Protocol: "http", Endpoint: "https://example.com/api"}
	if bt.Protocol != "http" || bt.Endpoint == "" { t.Error("fields") }
}
