package alpha20

import (
	"encoding/json"
	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSharedFeatureCorpus(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(current, "alpha20", "feature_negotiation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			ID       string   `json:"id"`
			Kind     string   `json:"kind"`
			Raw      string   `json:"raw"`
			Headers  []string `json:"headers"`
			Expected struct {
				Error    string             `json:"error"`
				Required []FeatureSelection `json:"required"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 44 {
		t.Fatal("missing shared fixtures")
	}
	for _, vector := range corpus.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			var err error
			if vector.Kind == "native-offer" {
				var offer FeatureOffer
				offer, err = ParseFeatureOffer(vector.Raw)
				if err == nil {
					var input struct {
						Offer []struct {
							ID        string
							Revisions []FeatureRevision
						} `json:"feature_offer"`
						Required []string `json:"required_features"`
					}
					if e := json.Unmarshal([]byte(vector.Raw), &input); e != nil {
						t.Fatal(e)
					}
					if len(input.Offer) != len(offer.Features()) || strings.Join(input.Required, ",") != strings.Join(offer.Required(), ",") {
						t.Fatal("offer mismatch")
					}
					for _, item := range input.Offer {
						if !reflect.DeepEqual(item.Revisions, offer.Features()[item.ID]) {
							t.Fatal("revision mismatch")
						}
					}
				}
			} else {
				var selected []FeatureSelection
				selected, err = ParseRequiredFeatureHeader(vector.Headers)
				if err == nil && !reflect.DeepEqual(selected, vector.Expected.Required) {
					t.Fatalf("requirements mismatch: %v / %v", selected, vector.Expected.Required)
				}
			}
			parserError := vector.Expected.Error == ErrNativeFeatureInvalid.Error() || vector.Expected.Error == ErrHTTPFeatureInvalid.Error()
			if parserError {
				if err == nil || err.Error() != vector.Expected.Error {
					t.Fatalf("wrong parser error: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRawEdgeCases(t *testing.T) {
	for _, raw := range []string{
		`{"feature_negotiation":1,"feature_\u006eegotiation":1}`,
		`{"feature_negotiation":true}`, `{"feature_negotiation":1e0}`, `{"feature_negotiation":1.0}`,
		`{"feature_negotiation":1,"required_features":["example.echo\ud800"]}`,
		`{"feature_negotiation":1,"required_features":["example.echo\udc00"]}`,
		"{\"feature_negotiation\":1,\"required_features\":[\"example.echo\xff\"]}",
		strings.Repeat("[", 70) + strings.Repeat("]", 70), `{}`,
	} {
		_, err := ParseFeatureOffer(raw)
		if raw == `{}` {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err != ErrNativeFeatureInvalid {
			t.Fatalf("accepted %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"example.echo=1\n", "example.echo\r=1", "example.echo=1\u2028"} {
		if _, err := ParseRequiredFeatureHeader([]string{raw}); err != ErrHTTPFeatureInvalid {
			t.Fatal(raw, err)
		}
	}
}

func TestDefensiveCopies(t *testing.T) {
	offer, err := ParseFeatureOffer(`{"feature_negotiation":1,"feature_offer":[{"id":"example.echo","revisions":[{"revision":1,"lifecycle":"stable"}]}],"required_features":["example.echo"]}`)
	if err != nil {
		t.Fatal(err)
	}
	offer.Features()["example.echo"][0].Revision = 9
	offer.Required()[0] = "other.id"
	if offer.Features()["example.echo"][0].Revision != 1 || offer.Required()[0] != "example.echo" {
		t.Fatal("parser state mutated")
	}
}
