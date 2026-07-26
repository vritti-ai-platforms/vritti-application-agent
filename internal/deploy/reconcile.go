package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// SpecHash is a stable content hash of a RunSpec, used to detect desired-state drift.
func SpecHash(spec dockerx.RunSpec) string {
	// Zero the hash label before hashing so it never feeds its own value back in.
	spec.Labels = nil
	b, _ := json.Marshal(spec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Apply reconciles a single long-running service: pull its image, and (re)create the container
// only when the desired spec differs from what is already running.
func Apply(ctx context.Context, dx *dockerx.Client, spec dockerx.RunSpec) error {
	if err := dx.PullImage(ctx, spec.Image); err != nil {
		return err
	}
	want := SpecHash(spec)
	have, err := dx.SpecHash(ctx, spec.Name)
	if err != nil {
		return err
	}
	if have == want {
		return nil // already converged
	}
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	}
	spec.Labels[dockerx.LabelSpecHash] = want
	return dx.Run(ctx, spec)
}
