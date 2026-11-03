// Package alpha20 provides experimental parsers, not session admission or feature advertisement.
package alpha20

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrNativeFeatureInvalid = errors.New("NCP-FEATURE-NEGOTIATION-INVALID")
	ErrHTTPFeatureInvalid   = errors.New("NWP-FEATURE-REQUIREMENTS-INVALID")
	invalidSyntax           = errors.New("invalid feature syntax")
	idPattern               = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_-]*)+$`)
	digitsPattern           = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
)

type FeatureRevision struct {
	Revision  uint16
	Lifecycle string
}
type FeatureSelection struct {
	ID       string
	Revision uint16
}
type FeatureOffer struct {
	features map[string][]FeatureRevision
	required []string
}

// Features returns a deep copy; callers cannot mutate parser-owned feature state.
func (o FeatureOffer) Features() map[string][]FeatureRevision {
	result := make(map[string][]FeatureRevision, len(o.features))
	for id, revisions := range o.features {
		result[id] = append([]FeatureRevision(nil), revisions...)
	}
	return result
}
func (o FeatureOffer) Required() []string { return append([]string(nil), o.required...) }

func need(ok bool) {
	if !ok {
		panic(invalidSyntax)
	}
}
func parseError(target error, err *error) {
	if failure := recover(); failure != nil {
		if failure != invalidSyntax {
			panic(failure)
		}
		*err = target
	}
}
func name(value any) string {
	id, ok := value.(string)
	need(ok && len(id) <= 96 && idPattern.MatchString(id))
	return id
}
func integer(value string) uint16 {
	need(digitsPattern.MatchString(value))
	number, err := strconv.ParseUint(value, 10, 16)
	need(err == nil)
	return uint16(number)
}
func members(value any, allowed ...string) map[string]any {
	object, ok := value.(map[string]any)
	need(ok)
	for key := range object {
		found := false
		for _, valid := range allowed {
			if key == valid {
				found = true
				break
			}
		}
		need(found)
	}
	return object
}
func array(value any, minimum, maximum int) []any {
	items, ok := value.([]any)
	need(ok && len(items) >= minimum && len(items) <= maximum)
	return items
}

// encoding/json replaces malformed surrogate escapes; reject them before decoding.
func strictUnicode(raw string) {
	need(utf8.ValidString(raw))
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		need(i < len(raw))
		if raw[i] != 'u' {
			continue
		}
		need(i+4 < len(raw))
		code, err := strconv.ParseUint(raw[i+1:i+5], 16, 16)
		need(err == nil)
		i += 4
		need(code < 0xdc00 || code > 0xdfff)
		if code >= 0xd800 && code <= 0xdbff {
			need(i+6 < len(raw) && raw[i+1:i+3] == `\u`)
			low, err := strconv.ParseUint(raw[i+3:i+7], 16, 16)
			need(err == nil && low >= 0xdc00 && low <= 0xdfff)
			i += 6
		}
	}
}

// Token recursion retains duplicate decoded keys and numeric lexemes. Feature-only:
// every legal numeric value is an unsigned decimal uint16, not general JSON numbers.
func readValue(decoder *json.Decoder, depth int) any {
	need(depth <= 64)
	token, err := decoder.Token()
	need(err == nil)
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				need(err == nil)
				key, ok := keyToken.(string)
				need(ok)
				_, duplicate := object[key]
				need(!duplicate)
				object[key] = readValue(decoder, depth+1)
			}
			end, err := decoder.Token()
			need(err == nil && end == json.Delim('}'))
			return object
		case '[':
			items := []any{}
			for decoder.More() {
				items = append(items, readValue(decoder, depth+1))
			}
			end, err := decoder.Token()
			need(err == nil && end == json.Delim(']'))
			return items
		default:
			need(false)
		}
	}
	if number, ok := token.(json.Number); ok {
		return integer(number.String())
	}
	return token
}

// ParseFeatureOffer reads a standalone feature block, not a complete Hello carrier.
func ParseFeatureOffer(raw string) (offer FeatureOffer, err error) {
	defer func() {
		if err != nil {
			offer = FeatureOffer{}
		}
	}()
	defer parseError(ErrNativeFeatureInvalid, &err)
	need(len(raw) <= 16384)
	strictUnicode(raw)
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	block := members(readValue(decoder, 0), "feature_negotiation", "feature_offer", "required_features")
	_, end := decoder.Token()
	need(end == io.EOF)
	if len(block) > 0 {
		need(block["feature_negotiation"] == uint16(1))
	}
	offer.features = map[string][]FeatureRevision{}
	if value, present := block["feature_offer"]; present {
		for _, value := range array(value, 0, 32) {
			item := members(value, "id", "revisions")
			id := name(item["id"])
			_, duplicate := offer.features[id]
			need(!duplicate)
			last := uint16(0)
			for _, value := range array(item["revisions"], 1, 16) {
				entry := members(value, "revision", "lifecycle")
				revision, ok := entry["revision"].(uint16)
				need(ok && revision > last)
				lifecycle, ok := entry["lifecycle"].(string)
				need(ok && (lifecycle == "experimental" || lifecycle == "stable" || lifecycle == "deprecated"))
				offer.features[id] = append(offer.features[id], FeatureRevision{revision, lifecycle})
				last = revision
			}
		}
	}
	if value, present := block["required_features"]; present {
		seen := map[string]bool{}
		for _, value := range array(value, 0, 32) {
			id := name(value)
			_, offered := offer.features[id]
			need(offered && !seen[id])
			seen[id] = true
			offer.required = append(offer.required, id)
		}
	}
	return offer, nil
}

// ParseRequiredFeatureHeader accepts raw instances before framework joining.
func ParseRequiredFeatureHeader(instances []string) (selected []FeatureSelection, err error) {
	defer func() {
		if err != nil {
			selected = nil
		}
	}()
	defer parseError(ErrHTTPFeatureInvalid, &err)
	need(len(instances) <= 1)
	if len(instances) == 0 {
		return []FeatureSelection{}, nil
	}
	raw := instances[0]
	need(len(raw) <= 4096)
	for _, code := range raw {
		need(code <= 127)
	}
	pairs := strings.Split(raw, ",")
	need(len(pairs) <= 32)
	previous := ""
	for _, pair := range pairs {
		parts := strings.Split(pair, "=")
		need(len(parts) == 2)
		id := name(parts[0])
		need(id > previous)
		selected = append(selected, FeatureSelection{id, integer(parts[1])})
		previous = id
	}
	return selected, nil
}
