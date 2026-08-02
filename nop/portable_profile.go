// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

const ndpClusterSplit = "NDP-CLUSTER-SPLIT"

// EvaluateOrchestration runs one deterministic NOP 0.9 portable-orchestrator transcript.
func EvaluateOrchestration(task map[string]any) map[string]any {
	nodes := map[string]map[string]any{}
	for _, raw := range anySlice(task["nodes"]) {
		node := object(raw)
		id := stringValue(node["id"])
		if _, exists := nodes[id]; exists {
			return emptyPortableFailure(ErrTaskDagInvalid)
		}
		nodes[id] = node
	}

	topology, ok := stablePortableTopology(nodes)
	if !ok {
		return emptyPortableFailure(ErrTaskDagCycle)
	}

	events := []string{}
	if boolValue(task["preflight"]) {
		events = append(events, "task:preflight")
		for _, id := range topology {
			available, present := nodes[id]["preflight_available"]
			if present && !boolValue(available) {
				events = append(events, "task:failed")
				return portableResult(events, "failed", ErrResourceInsufficient, nil, nil, nil, nil, nil)
			}
		}
	}

	events = append(events, "task:running")
	results := map[string]any{}
	states := map[string]string{}
	attemptCounts := map[string]int{}
	mappedParams := map[string]any{}
	taskRetries := intValue(task["max_retries"], 0)

	for _, id := range topology {
		node := nodes[id]
		if stringValue(task["cancel_before"]) == id {
			events = append(events, "task:cancelled")
			return portableResult(
				events, "cancelled", ErrTaskCancelled, nil,
				states, attemptCounts, mappedParams, nil,
			)
		}

		if condition, present := node["condition"]; present {
			context := rawMessageContext(results)
			matches, err := EvaluateCondition(stringValue(condition), context)
			if err != nil {
				states[id] = "failed"
				attemptCounts[id] = 0
				events = append(events, id+":failed", "task:failed")
				return portableResult(
					events, "failed", ErrConditionEvalError, nil,
					states, attemptCounts, mappedParams, nil,
				)
			}
			if !matches {
				states[id] = "skipped"
				attemptCounts[id] = 0
				events = append(events, id+":skipped")
				continue
			}
		}

		if mapping, present := node["input_mapping"]; present {
			params := map[string]any{}
			failed := false
			for name, path := range object(mapping) {
				resolved, err := ResolvePath(stringValue(path), rawMessageContext(results))
				if err != nil || len(resolved) == 0 {
					failed = true
					break
				}
				var value any
				if err := json.Unmarshal(resolved, &value); err != nil {
					failed = true
					break
				}
				params[name] = value
			}
			if failed {
				states[id] = "failed"
				attemptCounts[id] = 0
				events = append(events, id+":failed", "task:failed")
				return portableResult(
					events, "failed", ErrInputMappingError, nil,
					states, attemptCounts, mappedParams, nil,
				)
			}
			mappedParams[id] = params
		}

		maxRetries := intValue(node["max_retries"], taskRetries)
		scripted := anySlice(node["attempts"])
		finalError := ""
		completed := false
		count := 0
		for index, rawOutcome := range scripted {
			if index > maxRetries {
				break
			}
			outcome := object(rawOutcome)
			count++
			events = append(events, fmt.Sprintf("%s:attempt:%d", id, count))
			kind := stringValue(outcome["kind"])
			if kind == "success" {
				result := outcome["result"]
				if result == nil {
					result = map[string]any{}
				}
				results[id] = deepCopy(result)
				states[id] = "completed"
				events = append(events, id+":completed")
				completed = true
				break
			}

			if kind == "timeout" {
				finalError = ErrDelegateTimeout
			} else {
				finalError = stringValue(outcome["error_code"])
				if finalError == "" {
					finalError = ErrDelegateRejected
				}
			}
			retryable := kind == "timeout" || boolValue(outcome["retryable"])
			retryOn, hasRetryOn := node["retry_on"]
			selected := !hasRetryOn || containsString(stringSlice(retryOn), finalError)
			if retryable && selected && count <= maxRetries && index+1 < len(scripted) {
				events = append(events, id+":retrying")
				continue
			}
			states[id] = "failed"
			events = append(events, id+":failed")
			break
		}

		attemptCounts[id] = count
		if completed {
			continue
		}

		compensation, compensationError := compensatePortable(
			task, id, topology, nodes, states, &events,
		)
		events = append(events, "task:failed")
		if compensationError != "" {
			finalError = compensationError
		}
		if finalError == "" {
			finalError = ErrDelegateRejected
		}
		return portableResult(
			events, "failed", finalError, nil,
			states, attemptCounts, mappedParams, compensation,
		)
	}

	aggregate := aggregatePortable(task, topology, nodes, states, results)
	events = append(events, "task:completed")
	return portableResult(
		events, "completed", "", aggregate,
		states, attemptCounts, mappedParams, nil,
	)
}

// EvaluateRuntime evaluates one NOP 0.9 runtime/security profile category.
func EvaluateRuntime(category string, input map[string]any) map[string]any {
	switch category {
	case "callback":
		return evaluatePortableCallback(input)
	case "hmac":
		return evaluatePortableHMAC(input)
	case "lease":
		return evaluatePortableLease(input)
	case "delegation":
		return evaluatePortableDelegation(input)
	case "spawn_spec":
		return evaluatePortableSpawnSpec(input)
	case "lifecycle":
		return evaluatePortableLifecycle(input)
	case "dedup_key":
		return map[string]any{
			"value": ComputeDedupKey(
				stringValue(input["task_id"]),
				stringValue(input["dag_hash"]),
			),
		}
	default:
		panic(fmt.Sprintf("unknown NOP portable profile category: %s", category))
	}
}

// ComputeDedupKey returns SHA-256(task_id + NUL + dag_hash) as lowercase hex.
func ComputeDedupKey(taskID, dagHash string) string {
	sum := sha256.Sum256([]byte(taskID + "\x00" + dagHash))
	return hex.EncodeToString(sum[:])
}

func stablePortableTopology(nodes map[string]map[string]any) ([]string, bool) {
	indegree := make(map[string]int, len(nodes))
	outgoing := make(map[string][]string, len(nodes))
	for id := range nodes {
		indegree[id] = 0
		outgoing[id] = []string{}
	}
	for id, node := range nodes {
		for _, dependency := range stringSlice(node["depends_on"]) {
			if _, exists := nodes[dependency]; !exists {
				return nil, false
			}
			indegree[id]++
			outgoing[dependency] = append(outgoing[dependency], id)
		}
	}

	ready := []string{}
	for id, degree := range indegree {
		if degree == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)
	order := make([]string, 0, len(nodes))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)
		nextIDs := append([]string(nil), outgoing[id]...)
		sort.Strings(nextIDs)
		for _, next := range nextIDs {
			indegree[next]--
			if indegree[next] == 0 {
				ready = append(ready, next)
				sort.Strings(ready)
			}
		}
	}
	return order, len(order) == len(nodes)
}

func compensatePortable(
	task map[string]any,
	failedID string,
	topology []string,
	nodes map[string]map[string]any,
	states map[string]string,
	events *[]string,
) ([]string, string) {
	policy := stringValue(task["compensation_policy"])
	if policy != "best_effort" && policy != "strict" {
		return []string{}, ""
	}

	ancestors := map[string]bool{}
	var collect func(string)
	collect = func(id string) {
		for _, dependency := range stringSlice(nodes[id]["depends_on"]) {
			if !ancestors[dependency] {
				ancestors[dependency] = true
				collect(dependency)
			}
		}
	}
	collect(failedID)

	candidates := []string{}
	for i := len(topology) - 1; i >= 0; i-- {
		id := topology[i]
		if ancestors[id] && states[id] == "completed" {
			candidates = append(candidates, id)
		}
	}
	if policy == "strict" {
		for _, id := range candidates {
			if _, present := nodes[id]["compensate_action"]; !present {
				return []string{}, ErrCompensationNotSupported
			}
		}
	}

	order := []string{}
	for _, id := range candidates {
		node := nodes[id]
		if _, present := node["compensate_action"]; !present {
			continue
		}
		order = append(order, id)
		*events = append(*events, id+":compensating")
		if stringValue(node["compensation_outcome"]) == "failure" {
			states[id] = "compensation_failed"
			*events = append(*events, id+":compensation_failed")
			if policy == "strict" {
				return order, ErrCompensationFailed
			}
		} else {
			states[id] = "compensated"
			*events = append(*events, id+":compensated")
		}
	}
	return order, ""
}

func aggregatePortable(
	task map[string]any,
	topology []string,
	nodes map[string]map[string]any,
	states map[string]string,
	results map[string]any,
) any {
	hasOutgoing := map[string]bool{}
	for _, node := range nodes {
		for _, dependency := range stringSlice(node["depends_on"]) {
			hasOutgoing[dependency] = true
		}
	}

	values := []any{}
	for _, id := range topology {
		result, present := results[id]
		if !hasOutgoing[id] && states[id] == "completed" && present {
			values = append(values, deepCopy(result))
		}
	}
	if len(values) == 0 {
		return nil
	}
	if stringValue(task["aggregate"]) == "all" {
		return values
	}

	merged := map[string]any{}
	for _, raw := range values {
		value, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item := value[key]
			if stringValue(task["aggregate"]) == "merge_all" {
				existing, hasExisting := merged[key].([]any)
				incoming, isArray := item.([]any)
				if hasExisting && isArray {
					merged[key] = append(existing, deepCopy(incoming).([]any)...)
					continue
				}
			}
			merged[key] = deepCopy(item)
		}
	}
	return merged
}

func evaluatePortableCallback(input map[string]any) map[string]any {
	allowed := callbackDestinationAllowed(
		stringValue(input["url"]),
		stringSlice(input["resolved_ips"]),
	)
	if allowed {
		if redirect, present := input["redirect_url"]; present {
			allowed = callbackDestinationAllowed(
				stringValue(redirect),
				stringSlice(input["redirect_resolved_ips"]),
			)
		}
	}
	var err any
	if !allowed {
		err = ErrCallbackInvalid
	}
	return map[string]any{"allowed": allowed, "error": err}
}

func callbackDestinationAllowed(value string, addresses []string) bool {
	parsed, err := url.Parse(value)
	if err != nil ||
		!strings.EqualFold(parsed.Scheme, "https") ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil || !isPublicIP(ip) {
			return false
		}
	}
	return true
}

func isPublicIP(ip net.IP) bool {
	if ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] != 0 && v4[0] < 224
	}
	return true
}

func evaluatePortableHMAC(input map[string]any) map[string]any {
	signature, present := input["signature"]
	if !present || signature == nil {
		return map[string]any{"valid": false, "error": ErrCallbackHmacMissing}
	}

	key, err := base64.RawURLEncoding.DecodeString(stringValue(input["secret_base64url"]))
	if err != nil {
		return map[string]any{"valid": false, "error": ErrCallbackHmacInvalid}
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(stringValue(input["raw_body"])))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	valid := len(key) == 32 && hmac.Equal([]byte(expected), []byte(stringValue(signature)))
	var code any
	if !valid {
		code = ErrCallbackHmacInvalid
	}
	return map[string]any{"valid": valid, "error": code}
}

type portableLease struct {
	runnerNID string
	expiresAt int
}

func evaluatePortableLease(input map[string]any) map[string]any {
	leases := map[string]portableLease{}
	terminal := map[string]bool{}
	outcomes := []string{}
	for _, rawEvent := range anySlice(input["events"]) {
		event := object(rawEvent)
		at := intValue(event["at"], 0)
		switch stringValue(event["op"]) {
		case "claim":
			taskID := stringValue(event["task_id"])
			runner := stringValue(event["runner_nid"])
			seconds := clampLeaseSeconds(intValue(event["lease_seconds"], 0))
			lease, present := leases[taskID]
			if present && lease.expiresAt > at {
				if lease.runnerNID == runner {
					leases[taskID] = portableLease{runnerNID: runner, expiresAt: at + seconds}
					outcomes = append(outcomes, "granted")
				} else {
					outcomes = append(outcomes, "conflict")
				}
			} else {
				leases[taskID] = portableLease{runnerNID: runner, expiresAt: at + seconds}
				if present {
					outcomes = append(outcomes, "reclaimed")
				} else {
					outcomes = append(outcomes, "granted")
				}
			}
		case "renew":
			taskID := stringValue(event["task_id"])
			runner := stringValue(event["runner_nid"])
			seconds := clampLeaseSeconds(intValue(event["lease_seconds"], 0))
			lease, present := leases[taskID]
			if present && lease.expiresAt > at && lease.runnerNID == runner {
				leases[taskID] = portableLease{runnerNID: runner, expiresAt: at + seconds}
				outcomes = append(outcomes, "granted")
			} else {
				outcomes = append(outcomes, "conflict")
			}
		case "mark_terminal":
			terminal[portableTerminalKey(event)] = true
			outcomes = append(outcomes, "recorded")
		case "is_terminal":
			if terminal[portableTerminalKey(event)] {
				outcomes = append(outcomes, "terminal")
			} else {
				outcomes = append(outcomes, "pending")
			}
		}
	}
	return map[string]any{"outcomes": outcomes}
}

func portableTerminalKey(event map[string]any) string {
	return stringValue(event["dedup_key"]) + "\x00" + stringValue(event["node_id"])
}

func clampLeaseSeconds(value int) int {
	if value < 10 {
		return 10
	}
	if value > 600 {
		return 600
	}
	return value
}

func evaluatePortableDelegation(input map[string]any) map[string]any {
	parent := object(input["parent_scope"])
	delegated := object(input["delegated_scope"])
	if !stringSubset(stringSlice(delegated["nodes"]), stringSlice(parent["nodes"])) ||
		!stringSubset(stringSlice(delegated["actions"]), stringSlice(parent["actions"])) ||
		intValue(delegated["max_token_budget"], 0) > intValue(parent["max_token_budget"], 0) {
		return map[string]any{"targets": []string{}, "error": ErrDelegateScopeViolation}
	}

	targets := []string{}
	for _, rawAttempt := range anySlice(input["attempts"]) {
		attempt := object(rawAttempt)
		live := []map[string]any{}
		for _, rawCandidate := range anySlice(attempt["candidates"]) {
			candidate := object(rawCandidate)
			if boolValue(candidate["live"]) {
				live = append(live, candidate)
			}
		}
		if len(live) == 0 {
			return map[string]any{"targets": targets, "error": ErrDelegateRejected}
		}
		highest := intValue(live[0]["cluster_epoch"], 0)
		for _, candidate := range live[1:] {
			epoch := intValue(candidate["cluster_epoch"], 0)
			if epoch > highest {
				highest = epoch
			}
		}
		leaders := []map[string]any{}
		for _, candidate := range live {
			if intValue(candidate["cluster_epoch"], 0) == highest {
				leaders = append(leaders, candidate)
			}
		}
		if len(leaders) != 1 {
			return map[string]any{"targets": targets, "error": ndpClusterSplit}
		}
		targets = append(targets, stringValue(leaders[0]["nid"]))
	}
	return map[string]any{"targets": targets, "error": nil}
}

func evaluatePortableSpawnSpec(input map[string]any) map[string]any {
	spec := object(input["spawn_spec"])
	valid := strings.TrimSpace(stringValue(spec["image"])) != ""
	if valid {
		idle, hasIdle := spec["idle_timeout_seconds"]
		maxRuntime, hasMax := spec["max_runtime_seconds"]
		if hasIdle && hasMax && intValue(idle, 0) > intValue(maxRuntime, 0) {
			valid = false
		}
	}
	var err any
	if !valid {
		err = ErrSpawnSpecInvalid
	}
	return map[string]any{"error": err}
}

func evaluatePortableLifecycle(input map[string]any) map[string]any {
	if intValue(input["elapsed_seconds"], 0) >= intValue(input["max_runtime_seconds"], 0) {
		return map[string]any{"state": "failed", "error": ErrRuntimeMaxRuntime}
	}
	if intValue(input["idle_seconds"], 0) >= intValue(input["idle_timeout_seconds"], 0) {
		return map[string]any{"state": "failed", "error": ErrRuntimeIdleTimeout}
	}
	if stringValue(input["worker_terminal"]) == "done" {
		return map[string]any{"state": "completed", "error": nil}
	}
	return map[string]any{"state": "failed", "error": ErrDelegateRejected}
}

func portableResult(
	events []string,
	state string,
	errorCode string,
	aggregate any,
	states map[string]string,
	attempts map[string]int,
	mapped map[string]any,
	compensation []string,
) map[string]any {
	if events == nil {
		events = []string{}
	}
	if states == nil {
		states = map[string]string{}
	}
	if attempts == nil {
		attempts = map[string]int{}
	}
	if mapped == nil {
		mapped = map[string]any{}
	}
	if compensation == nil {
		compensation = []string{}
	}
	var errorValue any
	if errorCode != "" {
		errorValue = errorCode
	}
	return map[string]any{
		"events":             append([]string{}, events...),
		"terminal_state":     state,
		"error_code":         errorValue,
		"aggregate":          deepCopy(aggregate),
		"node_states":        states,
		"attempt_counts":     attempts,
		"mapped_params":      deepCopy(mapped),
		"compensation_order": append([]string{}, compensation...),
	}
}

func emptyPortableFailure(errorCode string) map[string]any {
	return portableResult(
		[]string{"task:failed"}, "failed", errorCode, nil,
		nil, nil, nil, nil,
	)
}

func rawMessageContext(values map[string]any) map[string]json.RawMessage {
	context := make(map[string]json.RawMessage, len(values))
	for key, value := range values {
		encoded, _ := json.Marshal(value)
		context[key] = encoded
	}
	return context
}

func object(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	return map[string]any{}
}

func anySlice(value any) []any {
	if result, ok := value.([]any); ok {
		return result
	}
	return []any{}
}

func stringSlice(value any) []string {
	raw := anySlice(value)
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		result = append(result, stringValue(item))
	}
	return result
}

func stringValue(value any) string {
	if result, ok := value.(string); ok {
		return result
	}
	return ""
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func intValue(value any, fallback int) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case json.Number:
		result, err := number.Int64()
		if err == nil {
			return int(result)
		}
	}
	return fallback
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func stringSubset(values, allowed []string) bool {
	set := make(map[string]bool, len(allowed))
	for _, value := range allowed {
		set[value] = true
	}
	for _, value := range values {
		if !set[value] {
			return false
		}
	}
	return true
}

func deepCopy(value any) any {
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result any
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil
	}
	return result
}
