package envelope

import (
	"encoding/json"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	raw := []byte(`{"hello":"world"}`)
	env, err := Sign(raw, "probe_result", "mci-1", "secret")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	gotEnv, got, err := Verify(encoded, "probe_result", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if gotEnv.KeyID != "mci-1" || string(got) != string(raw) {
		t.Fatalf("unexpected round trip: %#v %s", gotEnv, got)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	raw := []byte(`{"hello":"world"}`)
	env, err := Sign(raw, "probe_job", "mci-1", "secret")
	if err != nil {
		t.Fatal(err)
	}
	env.PayloadB64 += "A"
	encoded, _ := json.Marshal(env)
	if _, _, err := Verify(encoded, "probe_job", "secret"); err == nil {
		t.Fatal("tampered envelope unexpectedly verified")
	}
}

func TestPythonCompatibilityVector(t *testing.T) {
	data := []byte(`{"key_id":"k","kind":"probe_job","payload_b64":"eyJhIjoxfQ==","signature":"0b259643137e71a766965267c82f097296b6791da7e2ee42c0e987771a766fdd","version":1}`)
	env, raw, err := Verify(data, "probe_job", "s")
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyID != "k" || string(raw) != `{"a":1}` {
		t.Fatalf("python compatibility vector mismatch: %#v %s", env, raw)
	}
}
