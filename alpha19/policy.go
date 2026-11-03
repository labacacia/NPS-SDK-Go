// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

// Package alpha19 implements the transport-independent alpha.19 hardening
// decisions shared by the protocol runtimes and conformance runners.
package alpha19

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"
)

type Input = map[string]any
type Output = map[string]any

func NCP(in Input) Output {
	if _, ok := in["client_ping_ms"]; ok {
		offers := []float64{}
		for _, k := range []string{"client_ping_ms", "server_ping_ms"} {
			if n := num(in[k]); n > 0 {
				offers = append(offers, n)
			}
		}
		if len(offers) == 0 {
			return Output{"keepalive_enabled": false, "effective_interval_ms": nil}
		}
		v := offers[0]
		for _, n := range offers[1:] {
			if n < v {
				v = n
			}
		}
		if v < 1000 {
			v = 1000
		}
		return Output{"keepalive_enabled": true, "effective_interval_ms": v}
	}
	if events, ok := in["events"].([]any); ok {
		clock := num(in["last_valid_inbound_ms"])
		for _, raw := range events {
			e := obj(raw)
			if str(e["event"]) == "valid_inbound_frame" {
				clock = num(e["at_ms"])
			}
		}
		return Output{"last_valid_inbound_ms": clock}
	}
	if _, ok := in["queued_probe_count"]; ok {
		due := num(in["evaluate_at_ms"])-num(in["last_application_send_ms"]) >= num(in["effective_interval_ms"])
		if due && num(in["queued_probe_count"]) == 0 {
			return Output{"enqueue": Output{"frame": "0x07", "payload_length": float64(0)}, "queued_probe_count": float64(1)}
		}
		return Output{"queued_probe_count": num(in["queued_probe_count"])}
	}
	if _, ok := in["active_streams"]; ok {
		if num(in["evaluate_at_ms"]) >= num(in["last_valid_inbound_ms"])+3*num(in["effective_interval_ms"]) {
			return Output{"state": "closing", "error": "NCP-KEEPALIVE-TIMEOUT", "error_count": float64(1), "cancelled_streams": num(in["active_streams"]), "close_by_ms": num(in["evaluate_at_ms"]) + 500, "allow_later_application_frames": false}
		}
		return Output{"state": "open"}
	}
	if _, ok := in["payload_length"]; ok {
		if num(in["payload_length"]) != 0 {
			return Output{"accepted": false, "error": "NCP-FRAME-PAYLOAD-TOO-LARGE", "last_valid_inbound_ms": num(in["last_valid_inbound_ms"])}
		}
		return Output{"accepted": true, "last_valid_inbound_ms": num(in["received_at_ms"])}
	}
	if _, ok := in["early_data"]; ok {
		if str(in["carrier"]) == "quic" && !boolean(in["handshake_confirmed"]) {
			return Output{"accepted": false, "error": "NCP-EARLY-DATA-REJECTED", "retry_after_confirmation": true}
		}
		return Output{"accepted": true}
	}
	if _, ok := in["bound_nid"]; ok {
		if !boolean(in["handshake_confirmed"]) || str(in["bound_nid"]) != str(in["migrated_nid"]) {
			return Output{"migration_allowed": false, "session_preserved": false, "error": "NCP-NID-MISMATCH"}
		}
		send := num(in["carrier_credit_bytes"]) > 0 && num(in["ncp_window_cgn"]) > 0
		out := Output{"migration_allowed": true, "session_preserved": true, "send_allowed": send}
		if !send {
			if num(in["ncp_window_cgn"]) <= 0 {
				out["reason"] = "ncp_window_exhausted"
			} else {
				out["reason"] = "carrier_credit_exhausted"
			}
		}
		return out
	}
	panic("unknown NCP 0.12 input")
}

func normalizeSLA(sla Input, prefix string) (Output, []any) {
	out := Output{}
	diagnostics := []any{}
	if raw, ok := sla["p95_latency_ms"]; ok {
		n := num(raw)
		if n > 0 && n <= math.MaxUint32 && n == math.Trunc(n) {
			out["p95_latency_ms"] = n
		} else {
			diagnostics = append(diagnostics, prefix+"p95_latency_ms")
		}
	}
	if raw, ok := sla["availability"]; ok {
		var n float64
		fmt.Sscan(str(raw), &n)
		if n > 0 && n <= 1 {
			out["availability"] = str(raw)
		} else {
			diagnostics = append(diagnostics, prefix+"availability")
		}
	}
	if raw, ok := sla["sla_tier"]; ok {
		tier := str(raw)
		ranks := map[string]float64{"basic": 0, "standard": 1, "premium": 2}
		if rank, ok := ranks[tier]; ok {
			out["sla_tier"] = tier
			out["sla_tier_rank"] = rank
		} else {
			out["sla_tier_raw"] = tier
			out["sla_tier_rank"] = nil
		}
	}
	return out, diagnostics
}

func NWPMetadata(in Input) Output {
	if raw, ok := in["stability"]; ok {
		if raw == nil {
			return Output{"normalized": "stable", "diagnostics": []any{}}
		}
		v := str(raw)
		if v == "experimental" || v == "stable" || v == "deprecated" {
			return Output{"raw": v, "normalized": v, "rank_as_stable": v == "stable"}
		}
		return Output{"raw": v, "normalized": "experimental", "rank_as_stable": false}
	}
	if raw, ok := in["sla"]; ok {
		sla, d := normalizeSLA(obj(raw), "")
		return Output{"manifest_valid": true, "normalized_sla": sla, "diagnostics": d}
	}
	if raw, ok := in["billing"]; ok {
		b := obj(raw)
		profile := str(b["metering_profile"])
		if profile != "free" && profile != "metered" {
			profile = "metered"
		}
		out := Output{"metering_profile": profile}
		d := []any{}
		if profile == "free" {
			for _, k := range []string{"billing_unit", "price_hint", "currency"} {
				if _, ok := b[k]; ok {
					d = append(d, k)
				}
			}
		} else {
			if unit := str(b["billing_unit"]); unit != "" {
				out["billing_unit"] = unit
			} else {
				d = append(d, "billing_unit")
			}
			if price := str(b["price_hint"]); price != "" {
				if regexp.MustCompile(`^[A-Z]{3} [0-9]+(?:\.[0-9]+)?$`).MatchString(price) {
					if c, ok := b["currency"]; ok && str(c) != price[:3] {
						d = append(d, "currency")
					} else {
						out["price_hint"] = price
						if ok {
							out["currency"] = str(c)
						}
					}
				} else {
					d = append(d, "price_hint")
				}
			}
		}
		return Output{"normalized_billing": out, "diagnostics": d}
	}
	if _, ok := in["top_level"]; ok {
		base, _ := normalizeSLA(obj(obj(in["top_level"])["sla"]), "")
		override, d := normalizeSLA(obj(obj(in["action"])["sla"]), "action.sla.")
		for k, v := range override {
			base[k] = v
		}
		return Output{"effective_sla": base, "diagnostics": d}
	}
	panic("unknown NWP metadata input")
}

func NWPSubscription(in Input) Output {
	if raw, ok := in["policy"]; ok {
		p, r := obj(raw), obj(in["request"])
		def, max, renew := num(p["default_lease_seconds"]), num(p["max_lease_seconds"]), num(p["renew_before_seconds"])
		if def <= 0 || max <= 0 || def > max || renew >= max {
			return Output{"accepted": false, "error": "NWP-SUBSCRIBE-LEASE-INVALID", "state_mutated": false}
		}
		lease := def
		if v, ok := r["lease_seconds"]; ok {
			lease = num(v)
		}
		if lease <= 0 {
			return Output{"accepted": false, "error": "NWP-SUBSCRIBE-LEASE-INVALID", "state_mutated": false}
		}
		if lease > max {
			lease = max
		}
		expires := parseTime(str(in["accepted_at"])).Add(time.Duration(lease) * time.Second).Format(time.RFC3339)
		out := Output{"lease_seconds": lease, "expires_at": expires}
		if _, ok := r["lease_seconds"]; !ok {
			out["status"] = "open"
		}
		return out
	}
	if _, ok := in["owner_nid"]; ok {
		if str(in["owner_nid"]) != str(in["caller_nid"]) {
			return Output{"accepted": false, "error": "NWP-AUTH-NID-SCOPE-VIOLATION", "state_disclosed": false}
		}
		return Output{"accepted": true}
	}
	if _, ok := in["prior_seq"]; ok {
		return Output{"expires_at": parseTime(str(in["accepted_at"])).Add(time.Duration(num(in["lease_seconds"])) * time.Second).Format(time.RFC3339), "seq": num(in["prior_seq"]), "cursor": in["prior_cursor"]}
	}
	if _, ok := in["expires_at"]; ok {
		if !parseTime(str(in["now"])).Before(parseTime(str(in["expires_at"]))) {
			return Output{"accepted": false, "status": "closed", "error": "NWP-SUBSCRIBE-LEASE-EXPIRED", "terminal_event_count": float64(1)}
		}
		return Output{"accepted": true}
	}
	if op := str(in["operation"]); op == "renew" || op == "close" {
		for _, k := range []string{"anchor_ref", "filter", "type"} {
			if _, ok := in[k]; ok {
				return Output{"accepted": false, "error": "NWP-SUBSCRIBE-LEASE-INVALID", "state_mutated": false}
			}
		}
	}
	panic("unknown NWP subscription input")
}

func NIPRenewal(in Input) Output {
	if str(in["profile"]) == "standard" {
		open := parseTime(str(in["not_after"])).Sub(parseTime(str(in["now"]))) <= 7*24*time.Hour
		var err any = nil
		if !open {
			err = "NIP-CA-RENEWAL-TOO-EARLY"
		}
		return Output{"renewal_open": open, "error": err}
	}
	if str(in["profile"]) == "short-lived-edge" {
		w := math.Floor(num(in["original_validity_seconds"]) / 4)
		return Output{"renewal_open": num(in["remaining_seconds"]) <= w, "window_seconds": w}
	}
	if _, ok := in["current"]; ok {
		cur, req := obj(in["current"]), obj(in["requested"])
		allowed := subset(req["capabilities"], cur["capabilities"]) && subset(req["scope"], cur["scope"])
		if allowed {
			return Output{"issued": true}
		}
		return Output{"issued": false, "error": "NIP-CA-SCOPE-EXPANSION-DENIED"}
	}
	if _, ok := in["recorded"]; ok {
		r := obj(in["recorded"])
		if boolean(r["committed"]) && str(r["canonical_digest"]) == str(in["canonical_digest"]) {
			return Output{"serial": r["serial"], "new_issue_count": float64(0)}
		}
		return Output{"error": "NIP-CA-SERIAL-DUPLICATE", "new_issue_count": float64(0)}
	}
	if _, ok := in["old_ticket_not_after"]; ok {
		return Output{"old_ticket_not_after": in["old_ticket_not_after"]}
	}
	panic("unknown NIP renewal input")
}

func NIPRevocation(in Input) Output {
	if _, ok := in["cached"]; ok {
		c, n := obj(in["cached"]), obj(in["incoming"])
		replace := boolean(n["signature_valid"]) && parseTime(str(n["this_update"])).After(parseTime(str(c["this_update"])))
		if replace {
			return Output{"cache_replaced": true, "effective_outcome": n["outcome"]}
		}
		return Output{"cache_replaced": false, "effective_outcome": c["outcome"]}
	}
	consulted, d := []any{}, []any{}
	var now time.Time
	if in["now"] != nil {
		now = parseTime(str(in["now"]))
	}
	for _, raw := range arr(in["sources"]) {
		s := obj(raw)
		name, outcome := str(s["source"]), str(s["outcome"])
		consulted = append(consulted, name)
		if outcome == "unknown" {
			return Output{"valid": false, "error": "NIP-OCSP-UNKNOWN"}
		}
		if !now.IsZero() && s["next_update"] != nil && !now.Before(parseTime(str(s["next_update"]))) {
			d = append(d, name+"_stale")
			continue
		}
		if outcome == "revoked" {
			return Output{"valid": false, "error": "NIP-CERT-REVOKED"}
		}
		if outcome == "good" {
			out := Output{"valid": true, "consulted_sources": consulted}
			if len(d) > 0 {
				out["diagnostics"] = d
			}
			return out
		}
	}
	if str(in["revocation_mode"]) == "required" {
		return Output{"valid": false, "error": "NIP-REVOCATION-STATE-STALE"}
	}
	return Output{"valid": true, "consulted_sources": consulted}
}

func NIPAdvisory(in Input) Output {
	ident, ext := obj(in["ident"]), obj(in["certificate_extensions"])
	findings := []any{}
	add := func(field, err string) { findings = append(findings, Output{"field": field, "error": err}) }
	if str(ident["assurance_level"]) != str(ext["assurance_level"]) {
		add("assurance_level", "NIP-ASSURANCE-MISMATCH")
	}
	if !subset(ident["capabilities"], ext["capabilities"]) {
		add("capabilities", "NIP-CERT-CAPABILITIES-EXCEEDED")
	}
	if !subset(ident["node_roles"], ext["node_roles"]) {
		add("node_roles", "NIP-CERT-NODE-ROLES-MISMATCH")
	}
	if ident["ocsp_staple"] == nil {
		add("ocsp_staple", "NIP-OCSP-STAPLE-EXPIRED")
	}
	sort.Slice(findings, func(i, j int) bool { return str(obj(findings[i])["field"]) < str(obj(findings[j])["field"]) })
	return Output{"accepted_current_request": !boolean(in["phase3_enforcement"]), "findings": findings, "state_mutated": false}
}

func NDP(in Input) Output {
	if _, ok := in["commit"]; ok {
		if str(in["commit"]) == "success" {
			return Output{"acknowledged": true, "served_seq": num(in["incoming_seq"]), "persisted_seq": num(in["incoming_seq"])}
		}
		return Output{"acknowledged": false, "served_seq": num(in["persisted_seq"]), "persisted_seq": num(in["persisted_seq"]), "error": "NDP-STATE-UNAVAILABLE"}
	}
	if _, ok := in["now"]; ok {
		r := obj(in["record"])
		return Output{"live_entry": parseTime(str(r["fresh_until"])).After(parseTime(str(in["now"]))), "highest_seq": num(r["highest_seq"]), "ready": true}
	}
	if _, ok := in["restored_highest_seq"]; ok {
		if num(in["incoming_seq"]) < num(in["restored_highest_seq"]) {
			return Output{"accepted": false, "highest_seq": num(in["restored_highest_seq"]), "error": "NDP-GRAPH-SEQ-ROLLBACK"}
		}
		return Output{"accepted": true, "highest_seq": num(in["incoming_seq"])}
	}
	if _, ok := in["owners"]; ok {
		live := []Input{}
		top := -math.MaxFloat64
		for _, raw := range arr(in["owners"]) {
			o := obj(raw)
			if boolean(o["live"]) {
				live = append(live, o)
				if num(o["epoch"]) > top {
					top = num(o["epoch"])
				}
			}
		}
		leaders := []string{}
		for _, o := range live {
			if num(o["epoch"]) == top {
				leaders = append(leaders, str(o["nid"]))
			}
		}
		sort.Strings(leaders)
		if len(leaders) == 1 {
			return Output{"resolved_nid": leaders[0]}
		}
		return Output{"resolved_nid": nil, "error": "NDP-CLUSTER-SPLIT"}
	}
	if _, ok := in["snapshot_validation"]; ok {
		if str(in["snapshot_validation"]) == "valid" {
			return Output{"ready": true, "started_empty": false}
		}
		return Output{"ready": false, "started_empty": false, "error": "NDP-STATE-CORRUPT"}
	}
	if _, ok := in["profiles"]; ok {
		v := []any{}
		for _, x := range arr(in["profiles"]) {
			if str(x) == "local-dev" {
				v = append(v, "volatile")
			} else {
				v = append(v, "durable")
			}
		}
		return Output{"recovery": v}
	}
	if _, ok := in["revoked_origin"]; ok {
		r := obj(in["record"])
		return Output{"live": boolean(r["live"]) && str(r["origin"]) != str(in["revoked_origin"]), "highest_seq": num(r["highest_seq"])}
	}
	panic("unknown NDP input")
}

func NOP(in Input) Output {
	if _, ok := in["recorded"]; ok {
		r := obj(in["recorded"])
		if str(r["digest"]) == str(in["digest"]) {
			return Output{"state": r["state"], "dispatch_count": num(r["dispatch_count"]), "replayed": true}
		}
	}
	if _, ok := in["recorded_digest"]; ok {
		if str(in["digest"]) != str(in["recorded_digest"]) {
			return Output{"accepted": false, "error": "NOP-REPLAY-CONFLICT", "record_mutated": false}
		}
		return Output{"accepted": true}
	}
	if _, ok := in["incoming"]; ok {
		incoming := obj(in["incoming"])
		found := false
		for _, raw := range arr(in["records"]) {
			r := obj(raw)
			found = found || (str(r["caller_nid"]) == str(incoming["caller_nid"]) && str(r["task_id"]) == str(incoming["task_id"]))
		}
		return Output{"new_key": !found, "accepted": !found}
	}
	if _, ok := in["terminal_commit_ms"]; ok {
		if num(in["query_at_ms"]) >= num(in["terminal_commit_ms"])+1000*num(in["result_ttl_seconds"]) {
			return Output{"result": nil, "error": "NOP-TASK-RESULT-EXPIRED"}
		}
		return Output{"result": "retained"}
	}
	if _, ok := in["result_expired_at_ms"]; ok {
		retained := num(in["duplicate_at_ms"]) < num(in["result_expired_at_ms"])+1000*num(in["replay_tombstone_seconds"])
		if retained {
			return Output{"dispatch": false, "error": "NOP-TASK-RESULT-EXPIRED", "tombstone_retained": true}
		}
		return Output{"dispatch": true, "tombstone_retained": false}
	}
	if _, ok := in["capacity"]; ok {
		safe := []Input{}
		records := arr(in["records"])
		for _, raw := range records {
			r := obj(raw)
			if str(r["state"]) != "running" {
				safe = append(safe, r)
			}
		}
		if float64(len(records)) >= num(in["capacity"]) && len(safe) == 0 {
			return Output{"accepted": false, "evicted": []any{}, "error": "NOP-REPLAY-LIMIT"}
		}
		evicted := []any{}
		if len(safe) > 0 {
			evicted = append(evicted, safe[0]["key"])
		}
		return Output{"accepted": true, "evicted": evicted}
	}
	if _, ok := in["committed"]; ok {
		return Output{"state": obj(in["committed"])["state"], "late_event": "audit_only", "ttl_extended": false}
	}
	if _, ok := in["min_required"]; ok {
		results := []Input{}
		for _, raw := range arr(in["results"]) {
			r := obj(raw)
			score, ok := r["score"].(float64)
			if !ok || math.IsInf(score, 0) || math.IsNaN(score) {
				return Output{"error": "NOP-AGGREGATION-INVALID"}
			}
			results = append(results, r)
		}
		sort.Slice(results, func(i, j int) bool {
			a, b := num(results[i]["score"]), num(results[j]["score"])
			if a == b {
				return str(results[i]["node_id"]) < str(results[j]["node_id"])
			}
			return a > b
		})
		ids := []any{}
		for _, r := range results[:int(num(in["min_required"]))] {
			ids = append(ids, r["node_id"])
		}
		return Output{"selected_node_ids": ids}
	}
	if _, ok := in["topology_order"]; ok {
		by := map[string]Input{}
		for _, raw := range arr(in["results"]) {
			r := obj(raw)
			by[str(r["node_id"])] = r
		}
		agg := Output{}
		for _, raw := range arr(in["topology_order"]) {
			r := by[str(raw)]
			if r == nil || str(r["state"]) != "completed" {
				continue
			}
			for k, v := range obj(r["value"]) {
				left, lok := agg[k].([]any)
				right, rok := v.([]any)
				if lok && rok {
					agg[k] = append(append([]any{}, left...), right...)
				} else {
					agg[k] = v
				}
			}
		}
		return Output{"aggregated": agg, "inputs_mutated": false}
	}
	panic("unknown NOP input")
}

func obj(v any) Input {
	if v == nil {
		return Input{}
	}
	return v.(map[string]any)
}
func arr(v any) []any {
	if v == nil {
		return []any{}
	}
	return v.([]any)
}
func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func boolean(v any) bool { b, _ := v.(bool); return b }
func parseTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		panic(err)
	}
	return t
}
func subset(want, have any) bool {
	set := map[string]bool{}
	for _, v := range arr(have) {
		set[str(v)] = true
	}
	for _, v := range arr(want) {
		if !set[str(v)] {
			return false
		}
	}
	return true
}
