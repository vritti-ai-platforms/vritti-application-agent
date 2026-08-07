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

// Apply reconciles a single long-running service: pull its image, and (re)create the container only when
// the desired spec differs from what is already running — unless forceRecreate names this spec, in which case
// it is always re-run so it picks up freshly-fetched env even when the spec is byte-identical (the operator's
// per-service Recreate action).
func Apply(ctx context.Context, dx *dockerx.Client, spec dockerx.RunSpec, forceRecreate map[string]bool) error {
	if err := dx.PullImage(ctx, spec.Image); err != nil {
		return err
	}
	want := SpecHash(spec)
	if !forceRecreate[spec.Name] {
		have, err := dx.SpecHash(ctx, spec.Name)
		if err != nil {
			return err
		}
		if have == want {
			// Spec unchanged — but "converged" must also mean actually running. A crash that exhausted its
			// restart retries, or a manual `docker stop` (RestartPolicyUnlessStopped won't undo that), leaves a
			// matching-hash container stopped; a hash-only check would strand it down until the spec changes.
			if _, err := dx.EnsureStarted(ctx, spec.Name); err != nil {
				return err
			}
			return nil
		}
	}
	if spec.Labels == nil {
		spec.Labels = map[string]string{}
	}
	spec.Labels[dockerx.LabelSpecHash] = want
	return dx.Run(ctx, spec)
}
