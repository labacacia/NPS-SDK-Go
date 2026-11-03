// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package conformance

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	NodeL1 = "NPS-Node-L1"
	NodeL2 = "NPS-Node-L2"
)

type Case struct {
	ID          string `json:"id"`
	Profile     string `json:"profile"`
	Requirement string `json:"requirement"`
	Title       string `json:"title"`
	Optional    bool   `json:"optional"`
}

type CaseResult struct {
	ID      string `json:"id"`
	Result  string `json:"result"`
	Message string `json:"message,omitempty"`
}

type Actor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	NID     string `json:"nid,omitempty"`
}

type Run struct {
	Date        string `json:"date"`
	Environment string `json:"environment"`
}

type Summary struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Skip          int `json:"skip"`
	NotApplicable int `json:"na"`
}

type Manifest struct {
	Profile        string       `json:"profile"`
	ProfileVersion string       `json:"profile_version"`
	IUT            Actor        `json:"iut"`
	Peer           Actor        `json:"peer"`
	Run            Run          `json:"run"`
	Cases          []CaseResult `json:"cases"`
	Summary        Summary      `json:"summary"`
}

type Validation struct {
	Valid   bool
	Message string
}

func NewManifest(profile, iutName, iutVersion, iutNID, peerName, peerVersion string, results []CaseResult, environment string) Manifest {
	if environment == "" {
		environment = "unspecified"
	}
	version := "0.1"
	if profile == NodeL2 {
		version = "0.7"
	}
	summary := Summary{}
	for _, r := range results {
		switch r.Result {
		case "pass":
			summary.Pass++
		case "fail":
			summary.Fail++
		case "skip":
			summary.Skip++
		case "na":
			summary.NotApplicable++
		}
	}
	return Manifest{
		Profile:        profile,
		ProfileVersion: version,
		IUT:            Actor{Name: iutName, Version: iutVersion, NID: iutNID},
		Peer:           Actor{Name: peerName, Version: peerVersion},
		Run:            Run{Date: time.Now().UTC().Format(time.RFC3339Nano), Environment: environment},
		Cases:          append([]CaseResult(nil), results...),
		Summary:        summary,
	}
}

func (m Manifest) ToJSON() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

func CatalogForProfile(profile string) ([]Case, error) {
	switch profile {
	case NodeL1:
		return NodeL1Cases, nil
	case NodeL2:
		return NodeL2Cases, nil
	default:
		return nil, fmt.Errorf("unknown NPS conformance profile %q", profile)
	}
}

func ValidateManifest(m Manifest) Validation {
	catalog, err := CatalogForProfile(m.Profile)
	if err != nil {
		return Validation{false, err.Error()}
	}
	known := map[string]Case{}
	for _, c := range catalog {
		known[c.ID] = c
	}
	seen := map[string]bool{}
	validResults := map[string]bool{"pass": true, "fail": true, "skip": true, "na": true}
	for _, result := range m.Cases {
		c, ok := known[result.ID]
		if !ok {
			return Validation{false, fmt.Sprintf("Unknown conformance case id %q.", result.ID)}
		}
		if seen[result.ID] {
			return Validation{false, fmt.Sprintf("Duplicate conformance case id %q.", result.ID)}
		}
		seen[result.ID] = true
		if !validResults[result.Result] {
			return Validation{false, fmt.Sprintf("Case %q has invalid result %q.", result.ID, result.Result)}
		}
		if result.Result == "na" && !c.Optional {
			return Validation{false, fmt.Sprintf("Case %q is required and cannot be marked na.", result.ID)}
		}
		if result.Result == "na" && (result.ID == "TC-N2-AaaS-06" || result.ID == "TC-N2-AaaS-07") && strings.TrimSpace(result.Message) == "" {
			return Validation{false, fmt.Sprintf("Case %q requires a non-empty message for a SHOULD exception.", result.ID)}
		}
	}
	var missing []string
	for _, c := range catalog {
		if !seen[c.ID] {
			missing = append(missing, c.ID)
		}
	}
	if len(missing) > 0 {
		return Validation{false, "Missing conformance case results: " + strings.Join(missing, ", ") + "."}
	}
	for _, result := range m.Cases {
		if result.Result == "fail" || result.Result == "skip" {
			return Validation{false, "Conformance manifest contains fail or skip results."}
		}
	}
	expectedVersion := "0.1"
	if m.Profile == NodeL2 {
		expectedVersion = "0.7"
	}
	if m.ProfileVersion != expectedVersion {
		return Validation{false, fmt.Sprintf("Profile %q requires manifest version %q.", m.Profile, expectedVersion)}
	}
	expectedSummary := Summary{}
	for _, result := range m.Cases {
		switch result.Result {
		case "pass":
			expectedSummary.Pass++
		case "fail":
			expectedSummary.Fail++
		case "skip":
			expectedSummary.Skip++
		case "na":
			expectedSummary.NotApplicable++
		}
	}
	if m.Summary != expectedSummary {
		return Validation{false, "Conformance manifest summary does not match case results."}
	}
	if m.Profile == NodeL2 {
		results := map[string]string{}
		for _, result := range m.Cases {
			results[result.ID] = result.Result
		}
		families := [][]string{
			{"TC-N2-Tls-01", "TC-N2-Tls-02", "TC-N2-Tls-03", "TC-N2-Tls-04"},
			{"TC-N2-BridgeIn-01", "TC-N2-BridgeIn-02", "TC-N2-BridgeIn-03", "TC-N2-BridgeIn-04", "TC-N2-BridgeIn-05", "TC-N2-BridgeIn-06"},
			{"TC-N2-HA-01", "TC-N2-HA-02", "TC-N2-HA-03", "TC-N2-HA-04", "TC-N2-HA-05", "TC-N2-HA-06"},
			{"TC-N2-HA-07", "TC-N2-HA-08"},
		}
		for _, family := range families {
			want := results[family[0]]
			if want != "pass" && want != "na" {
				return Validation{false, fmt.Sprintf("L2 case family %q must be all pass or all na.", family[0])}
			}
			for _, id := range family[1:] {
				if results[id] != want {
					return Validation{false, fmt.Sprintf("L2 case family %q must be all pass or all na.", family[0])}
				}
			}
		}
		if (results["TC-N2-HA-01"] == "na") == (results["TC-N2-HA-09"] == "na") {
			return Validation{false, "L2 multi-Anchor HA and single-Anchor compatibility cases must have opposite applicability."}
		}
	}
	return Validation{true, "Conformance manifest is valid."}
}

func c(id, profile, requirement, title string, optional ...bool) Case {
	opt := false
	if len(optional) > 0 {
		opt = optional[0]
	}
	return Case{ID: id, Profile: profile, Requirement: requirement, Title: title, Optional: opt}
}

var NodeL1Cases = []Case{
	c("TC-N1-NCP-01", NodeL1, "N1-NCP-01", "Tier-1 JSON frame round-trip"),
	c("TC-N1-NCP-02", NodeL1, "N1-NCP-02", "Hello + Anchor handshake"),
	c("TC-N1-NCP-03", NodeL1, "N1-NCP-03", "Loopback listener default"),
	c("TC-N1-NCP-04", NodeL1, "N1-NCP-04", "Tier-2 negotiation hygiene"),
	c("TC-N1-NIP-01", NodeL1, "N1-NIP-01", "Root keypair generation and permission"),
	c("TC-N1-NIP-02", NodeL1, "N1-NIP-02", "IdentFrame sign and verify"),
	c("TC-N1-NIP-03", NodeL1, "N1-NIP-03", "NID format"),
	c("TC-N1-NIP-04", NodeL1, "N1-NIP-04", "Sub-NID issuance", true),
	c("TC-N1-NDP-01", NodeL1, "N1-NDP-01", "AnnounceFrame carries activation_mode"),
	c("TC-N1-NDP-02", NodeL1, "N1-NDP-02", "AnnounceFrame signature"),
	c("TC-N1-NDP-03", NodeL1, "N1-NDP-03", "ResolveFrame response"),
	c("TC-N1-NDP-04", NodeL1, "N1-NDP-04", "GraphFrame topology snapshot", true),
	c("TC-N1-NWP-01", NodeL1, "N1-NWP-01", "Inbox accepts ActionFrame"),
	c("TC-N1-NWP-02", NodeL1, "N1-NWP-02", "Inbox persists across restart"),
	c("TC-N1-NWP-03", NodeL1, "N1-NWP-03", "NWP pull serves inbox"),
	c("TC-N1-NWP-04", NodeL1, "N1-NWP-04", "100 QPS baseline"),
	c("TC-N1-NWP-05", NodeL1, "N1-NWP-05", "Push path", true),
	c("TC-N1-OBS-01", NodeL1, "N1-OBS-01", "Frame log entry per direction"),
	c("TC-N1-OBS-02", NodeL1, "N1-OBS-02", "Log entry fields"),
	c("TC-N1-OBS-03", NodeL1, "N1-OBS-03", "Log destination flexibility"),
}

var NodeL2Cases = []Case{
	c("TC-N2-AaaS-01", NodeL2, "L2-01", "Internal work uses NOP TaskFrame"),
	c("TC-N2-AaaS-02", NodeL2, "L2-02", "OpenTelemetry TaskFrame context injection"),
	c("TC-N2-AaaS-03", NodeL2, "L2-03", "CGN-Estimate budget and token_est response"),
	c("TC-N2-AaaS-04", NodeL2, "L2-04", "NOP preflight gates worker dispatch"),
	c("TC-N2-AaaS-05", NodeL2, "L2-05", "NOP retry and timeout semantics"),
	c("TC-N2-AaaS-06", NodeL2, "L2-06", "Asynchronous Action lifecycle", true),
	c("TC-N2-AaaS-07", NodeL2, "L2-07", "AlignStream CGN back-pressure", true),
	c("TC-N2-AnchorTopo-01", NodeL2, "L2-08", "Snapshot of a 3-member cluster"),
	c("TC-N2-AnchorTopo-02", NodeL2, "L2-08", "Version monotonicity across joins"),
	c("TC-N2-AnchorTopo-03", NodeL2, "L2-08", "Sub-Anchor member surfaces"),
	c("TC-N2-AnchorStream-01", NodeL2, "L2-08", "member_joined on NDP Announce"),
	c("TC-N2-AnchorStream-02", NodeL2, "L2-08", "member_left on NDP TTL expiry"),
	c("TC-N2-AnchorStream-03", NodeL2, "L2-08", "Resume from topology.since_version"),
	c("TC-N2-AnchorTopo-04", NodeL2, "L2-08", "Unauthorized topology access"),
	c("TC-N2-AnchorTopo-05", NodeL2, "L2-08", "Depth cap exceeded"),
	c("TC-N2-AnchorTopo-06", NodeL2, "L2-08", "Unsupported topology scope"),
	c("TC-N2-AnchorTopo-07", NodeL2, "L2-08", "Unsupported topology filter"),
	c("TC-N2-AnchorTopo-08", NodeL2, "L2-08", "Unsupported reserved topology type"),
	c("TC-N2-AnchorStream-04", NodeL2, "L2-08", "resync_required when version is too old"),
	c("TC-N2-Tls-01", NodeL2, "NPS-RFC-0006", "ALPN nps/1.0 negotiated over TLS 1.3", true),
	c("TC-N2-Tls-02", NodeL2, "NPS-RFC-0006", "Mutual TLS required", true),
	c("TC-N2-Tls-03", NodeL2, "NPS-RFC-0006", "Client cert trust anchor and NID binding", true),
	c("TC-N2-Tls-04", NodeL2, "NPS-RFC-0006", "IdentFrame/certificate NID mismatch", true),
	c("TC-N2-BridgeIn-01", NodeL2, "NPS-CR-0010", "MCP inbound required method set", true),
	c("TC-N2-BridgeIn-02", NodeL2, "NPS-CR-0010", "gRPC inbound round-trip", true),
	c("TC-N2-BridgeIn-03", NodeL2, "NPS-CR-0010", "A2A inbound round-trip", true),
	c("TC-N2-BridgeIn-04", NodeL2, "NPS-CR-0010", "Bare action resolution and ambiguity rejection", true),
	c("TC-N2-BridgeIn-05", NodeL2, "NPS-CR-0010", "Foreign-protocol error mapping", true),
	c("TC-N2-BridgeIn-06", NodeL2, "NPS-CR-0010", "Undeclared protocol or direction refusal", true),
	c("TC-N2-HA-01", NodeL2, "NPS-CR-0009", "cluster_epoch on topology read surfaces", true),
	c("TC-N2-HA-02", NodeL2, "NPS-CR-0009", "Planned anchor_failover wire shape", true),
	c("TC-N2-HA-03", NodeL2, "NPS-CR-0009", "Active-loss failover is terminal", true),
	c("TC-N2-HA-04", NodeL2, "NPS-CR-0009", "Quorum-loss wire shape and read-only mode", true),
	c("TC-N2-HA-05", NodeL2, "NPS-CR-0009", "Standby rejects topology writes", true),
	c("TC-N2-HA-06", NodeL2, "NPS-CR-0009", "Superseded leader is epoch fenced", true),
	c("TC-N2-HA-07", NodeL2, "NPS-CR-0009", "Registry resolves highest cluster_epoch", true),
	c("TC-N2-HA-08", NodeL2, "NPS-CR-0009", "Equal-epoch split-brain rejection", true),
	c("TC-N2-HA-09", NodeL2, "NPS-CR-0009", "Single-Anchor epoch-one compatibility", true),
}
