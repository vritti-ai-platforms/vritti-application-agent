package agentcrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// OpenSealed decrypts a secret an operator sealed to this agent's X25519 public key.
//
// The admin UI seals with libsodium's crypto_box_seal (anonymous box): the ciphertext is
// bound to the agent's sealing public key, so cloud stores bytes it can never read and the
// agent is the only party able to open them. `sealedB64` is base64(ephemeralPub || box).
func (k *Keys) OpenSealed(sealedB64 string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, err
	}
	plain, ok := box.OpenAnonymous(nil, sealed, &k.SealPub, &k.SealPriv)
	if !ok {
		return nil, errors.New("sealed secret failed to open (wrong key or corrupt ciphertext)")
	}
	return plain, nil
}

// VerifyDeployment checks a signature made by cloud with the deployment's private key.
// `deploymentPubB64` is the deployment PUBLIC key delivered at enrollment; this is how the
// agent authenticates that a command/desired-state genuinely came from cloud.
func VerifyDeployment(deploymentPubB64 string, msg []byte, sigB64 string) bool {
	pub, err := base64.StdEncoding.DecodeString(deploymentPubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
