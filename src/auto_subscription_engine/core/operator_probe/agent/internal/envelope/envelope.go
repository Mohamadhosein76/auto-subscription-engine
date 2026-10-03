package envelope

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

type Envelope struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	KeyID      string `json:"key_id"`
	PayloadB64 string `json:"payload_b64"`
	Signature  string `json:"signature"`
}

func macInput(version int, kind, payloadB64 string) []byte {
	return []byte(fmt.Sprintf("%d\n%s\n%s", version, kind, payloadB64))
}

func Sign(raw []byte, kind, keyID, secret string) (Envelope, error) {
	if secret == "" {
		return Envelope{}, errors.New("probe signing secret is empty")
	}
	payload := base64.StdEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(macInput(1, kind, payload))
	return Envelope{
		Version:    1,
		Kind:       kind,
		KeyID:      keyID,
		PayloadB64: payload,
		Signature:  hex.EncodeToString(mac.Sum(nil)),
	}, nil
}

func Verify(data []byte, expectedKind, secret string) (Envelope, []byte, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, nil, fmt.Errorf("decode envelope: %w", err)
	}
	if env.Version != 1 || env.Kind != expectedKind {
		return Envelope{}, nil, errors.New("unexpected envelope version or kind")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(macInput(env.Version, env.Kind, env.PayloadB64))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(env.Signature), []byte(expected)) {
		return Envelope{}, nil, errors.New("invalid envelope signature")
	}
	raw, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("decode payload: %w", err)
	}
	return env, raw, nil
}
