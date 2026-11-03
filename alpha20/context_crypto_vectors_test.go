package alpha20

// Frozen byte verification only; this is not a general JCS or admission verifier.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/labacacia/NPS-sdk-go/internal/testfixture"
	"os"
	"runtime"
	"testing"
)

func TestFrozenContextCrypto(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	path, err := testfixture.ConformanceFile(current, "alpha20", "context_crypto_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Key struct {
			Seed   string `json:"seed_hex"`
			Public string `json:"public_spki_der_hex"`
		} `json:"test_key"`
		Vectors []struct {
			ID        string `json:"id"`
			Request   string `json:"request_jcs"`
			Digest    string `json:"request_digest"`
			Payload   string `json:"payload_jcs"`
			Input     string `json:"signature_input_hex"`
			Signature string `json:"signature"`
			Envelope  string `json:"envelope_json"`
			Carrier   string `json:"carrier_base64url"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	fromHex := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	key, err := x509.ParsePKIXPublicKey(fromHex(corpus.Key.Public))
	if err != nil {
		t.Fatal(err)
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatal("not Ed25519")
	}
	private := ed25519.NewKeyFromSeed(fromHex(corpus.Key.Seed))
	if len(corpus.Vectors) != 6 {
		t.Fatal("missing fixtures")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			digest := sha256.Sum256([]byte("NPS-INVOKE-REQUEST/1\x00" + v.Request))
			if "sha256:"+hex.EncodeToString(digest[:]) != v.Digest {
				t.Fatal("request digest mismatch")
			}
			input := []byte("NPS-CONTEXT-PROJECTION/1\x00" + v.Payload)
			if !bytes.Equal(input, fromHex(v.Input)) {
				t.Fatal("input mismatch")
			}
			signature, err := base64.RawURLEncoding.Strict().DecodeString(v.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(public, input, signature) || !bytes.Equal(ed25519.Sign(private, input), signature) {
				t.Fatal("signature mismatch")
			}
			carrier, err := base64.RawURLEncoding.Strict().DecodeString(v.Carrier)
			if err != nil {
				t.Fatal(err)
			}
			if string(carrier) != v.Envelope {
				t.Fatal("carrier mismatch")
			}
			for _, wrong := range []string{v.Payload, "NPS-CONTEXT-PROJECTION/1" + v.Payload, "NPS-INVOKE-REQUEST/1\x00" + v.Payload, string(input) + " "} {
				if ed25519.Verify(public, []byte(wrong), signature) {
					t.Fatal("accepted wrong domain/bytes")
				}
			}
			signature[0] ^= 1
			if ed25519.Verify(public, input, signature) {
				t.Fatal("accepted bad signature")
			}
		})
	}
}
