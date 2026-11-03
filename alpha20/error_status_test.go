package alpha20_test

import (
	"encoding/json"
	"github.com/labacacia/NPS-sdk-go/core"
	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	"github.com/labacacia/NPS-sdk-go/ncp"
	"github.com/labacacia/NPS-sdk-go/nip"
	"github.com/labacacia/NPS-sdk-go/nop"
	"github.com/labacacia/NPS-sdk-go/nwp"
	"os"
	"runtime"
	"testing"
)

func TestAlpha20ErrorStatuses(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(current, "alpha20", "error_status_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Code, Status string
			HTTP         int
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 17 {
		t.Fatal("missing mappings")
	}
	maps := map[string]map[string]string{"NCP": ncp.NcpErrorToNpsStatus, "NWP": nwp.NwpErrorToNpsStatus, "NIP": nip.NipErrorToNpsStatus, "NOP": nop.NopErrorToNpsStatus}
	for _, v := range corpus.Cases {
		t.Run(v.Code, func(t *testing.T) {
			actual, ok := maps[v.Code[:3]][v.Code]
			if !ok || actual != v.Status || core.ToHttpStatus(actual) != v.HTTP {
				t.Fatalf("wrong mapping %s: %s", v.Code, actual)
			}
		})
	}
}
