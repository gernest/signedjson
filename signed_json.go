package signedjson

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// NACL_ED25519 default algorithm
const NACL_ED25519 = "ed25519"

// SupportedAlgorithms a list of supported algorithms
var SupportedAlgorithms = []string{NACL_ED25519}

// Key contains keys used to sign and verify messages,
type Key struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	Version    string
	Alg        string
}

// KeyID returns a string which is used to store the signature.
func (key *Key) KeyID() string {
	return fmt.Sprintf("%s:%s", key.Alg, key.Version)
}

// New generates a new private/public key and returns a *Key instance that uses
// the given version.
func New(version string) (*Key, error) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Key{
		PublicKey:  public,
		PrivateKey: private,
		Alg:        NACL_ED25519,
		Version:    version,
	}, nil
}

func DecodeBase64(v string) ([]byte, error) {
	e := base64.StdEncoding.WithPadding(base64.NoPadding)
	return e.DecodeString(v)
}

func EncodeBase64(v []byte) string {
	e := base64.StdEncoding.WithPadding(base64.NoPadding)
	return e.EncodeToString(v)
}

// Message represents arbitrary decoded json object. Note that maps are passed
// by reference in go. Key.Sign and Key.Verify modifies the passed object so be
// careful make sure you have a copy before passing this object to the mentioned
// methods.
type Message map[string]interface{}

func (m Message) SignatureID(name string) []string {
	s, ok := m["signatures"]
	if !ok {
		return nil
	}
	sig := s.(map[string]interface{})
	serv, ok := sig[name]
	if !ok {
		return nil
	}
	sv := serv.(map[string]string)
	var o []string
	for k := range sv {
		algo := strings.Split(k, ":")[0]
		if in(algo, SupportedAlgorithms...) {
			o = append(o, k)
		}
	}
	return o
}

func in(key string, v ...string) bool {
	for _, s := range v {
		if key == s {
			return true
		}
	}
	return false
}

// Sign signs json object v according to matrix specification
func (key *Key) Sign(object Message, signatureName string) error {
	var signatures map[string]interface{}
	if s, ok := object["signatures"]; ok {
		sm, ok := s.(map[string]interface{})
		if !ok {
			return errors.New("signedjson: bad signatures object")
		}
		signatures = sm
		delete(object, "signatures")
	} else {
		signatures = make(map[string]interface{})
	}

	var unsigned map[string]interface{}
	if s, ok := object["unsigned"]; ok {
		sm, ok := s.(map[string]interface{})
		if !ok {
			return errors.New("signedjson: bad unsigned object")
		}
		unsigned = sm
		delete(object, "unsigned")
	}
	messageBytes, err := json.Marshal(object)
	if err != nil {
		return err
	}
	signed := ed25519.Sign(key.PrivateKey, messageBytes)
	signatureBase64 := EncodeBase64(signed[:ed25519.SignatureSize])
	keyID := fmt.Sprintf("%s:%s", key.Alg, key.Version)
	if u, ok := signatures[signatureName]; ok {
		um, ok := u.(map[string]interface{})
		if !ok {
			return errors.New("signedjson: bad object found on key " + signatureName)
		}
		um[keyID] = signatureBase64
	} else {
		signatures[signatureName] = map[string]interface{}{
			keyID: signatureBase64,
		}
	}
	object["signatures"] = signatures
	if unsigned != nil {
		object["unsigned"] = unsigned
	}
	return nil
}

// Verify returns nil if message was signed by the key pair for the public key
// stored in this struct.
func (key *Key) Verify(message Message, signatureName string) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = errors.New("signedjson: failed validation")
		}
	}()
	sign, ok := message["signatures"]
	if !ok {
		return errors.New("signedjson: missing signatures object")
	}
	signature := sign.(map[string]interface{})
	keyID := key.KeyID()
	sign, ok = signature[signatureName]
	if !ok {
		return errors.New("signedjson: missing signature :[" + signatureName + "] object")
	}
	signBase64 := sign.(map[string]interface{})[keyID].(string)
	sig, err := DecodeBase64(signBase64)
	if err != nil {
		return err
	}
	delete(message, "signatures")
	delete(message, "unsigned")
	buf, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key.PublicKey, buf, sig) {
		return errors.New("signedjson: failed validation")
	}
	return nil
}

// DecodeVerifyKeyBytes returns *Key with verify as public key.
func DecodeVerifyKeyBytes(keyID string, verify []byte) (*Key, error) {
	p := strings.Split(keyID, ":")
	if len(p) != 2 {
		return nil, errors.New("signedjson: bad key_id string")
	}
	if p[0] != NACL_ED25519 {
		return nil, errors.New("signedjson: unsupported algorithm -" + p[0])
	}
	return &Key{
		Alg:       p[0],
		Version:   p[1],
		PublicKey: verify,
	}, nil
}

// DecodeSigningKeyBase64 returns a Key with PrivateKey decoded from base64
// encoded key.
func DecodeSigningKeyBase64(alg, version, key string) (*Key, error) {
	if alg != NACL_ED25519 {
		return nil, errors.New("signedjson: unsupported algorithm -" + alg)
	}
	b, err := DecodeBase64(key)
	if err != nil {
		return nil, err
	}
	return &Key{
		PrivateKey: b,
		Alg:        alg,
		Version:    version,
	}, nil
}

// DecodeVerifyKeyBase64 returns a Key with PublicKey decoded from base64
// encoded key.
func DecodeVerifyKeyBase64(alg, version, key string) (*Key, error) {
	if alg != NACL_ED25519 {
		return nil, errors.New("signedjson: unsupported algorithm -" + alg)
	}
	b, err := DecodeBase64(key)
	if err != nil {
		return nil, err
	}
	return &Key{
		PublicKey: b,
		Alg:       alg,
		Version:   version,
	}, nil
}
