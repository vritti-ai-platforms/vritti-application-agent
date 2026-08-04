package deploy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// webRoot is the on-host dir the managed edge serves for the wildcard (*.<base>) tenant origin:
// core-web at its root and each module-federation remote under its subdir. Bind-mounted into nginx
// read-only at /var/www/core-web.
func webRoot(stackRoot string) string {
	return filepath.Join(stackRoot, "www", "core-web")
}

// SyncWebBundles pulls each web artifact (core-web + entitled MF remotes) from its OCI registry and
// extracts it into the wildcard web root: Path "" → the SPA at the root, a non-empty Path → that
// subdir (so core-web loads the remote same-origin at /<path>/mf-manifest.json). Each bundle is
// pulled only when its registry digest differs from the last one extracted, so steady-state ticks do
// no work. Returns whether anything changed (so the caller can decide to reload nginx).
func SyncWebBundles(ctx context.Context, bundles []cloudapi.WebBundle, stackRoot string) (bool, error) {
	changed := false
	for _, b := range bundles {
		c, err := syncWebBundle(ctx, b, stackRoot)
		if err != nil {
			return changed, fmt.Errorf("web bundle %s: %w", b.Artifact, err)
		}
		changed = changed || c
	}
	// oras pull leaves the extracted tree mode 750 root:root, but nginx workers run as the unprivileged
	// `nginx` user and only bind-mount the web root read-only — without world traverse/read they hit
	// "stat() … (13: Permission denied)" on index.html and every *.<base> host 500s. Make the whole tree
	// world-readable (a+rX) every reconcile; it's cheap and idempotent.
	if err := makeWorldReadable(webRoot(stackRoot)); err != nil {
		return changed, fmt.Errorf("web root permissions: %w", err)
	}
	return changed, nil
}

// makeWorldReadable walks root setting directories to 0755 and files to 0644 (a+rX semantics), so the
// unprivileged nginx worker can traverse + read every served static asset. Idempotent; a not-yet-created
// root is a no-op.
func makeWorldReadable(root string) error {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	})
}

// syncWebBundle pulls one artifact and extracts it, skipping the pull when the recorded digest for
// this destination already matches the registry.
func syncWebBundle(ctx context.Context, b cloudapi.WebBundle, stackRoot string) (bool, error) {
	repo, reference, err := newBundleRepo(b.Artifact)
	if err != nil {
		return false, err
	}

	// Cheap HEAD: resolve the manifest digest and short-circuit if we already have it extracted.
	desc, err := repo.Resolve(ctx, reference)
	if err != nil {
		return false, fmt.Errorf("resolve: %w", err)
	}
	marker := bundleMarker(stackRoot, b.Path)
	if existing, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(existing)) == desc.Digest.String() {
		return false, nil
	}

	// Pull the artifact into a temp file store; oras restores the packed tarball by its title.
	tmp, err := os.MkdirTemp("", "webbundle-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	fs, err := file.New(tmp)
	if err != nil {
		return false, err
	}
	defer fs.Close()
	if _, err := oras.Copy(ctx, repo, reference, fs, reference, oras.DefaultCopyOptions); err != nil {
		return false, fmt.Errorf("pull: %w", err)
	}

	tarball, err := findTarball(tmp)
	if err != nil {
		return false, err
	}
	dest := filepath.Join(webRoot(stackRoot), b.Path)
	// A remote lives in its own subdir we fully own, so replace it wholesale to drop stale assets.
	// The host (Path "") is extracted over the root without wiping — it must not delete remote subdirs.
	if b.Path != "" {
		if err := os.RemoveAll(dest); err != nil {
			return false, err
		}
	}
	if err := extractTarGz(tarball, dest); err != nil {
		return false, err
	}

	if err := os.MkdirAll(filepath.Dir(marker), 0o750); err != nil {
		return false, err
	}
	if err := os.WriteFile(marker, []byte(desc.Digest.String()), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// hostBundleReady reports whether the host (core-web) bundle has been successfully extracted at least
// once — used to decide whether a later pull failure is fatal (first provision) or best-effort.
func hostBundleReady(stackRoot string) bool {
	_, err := os.Stat(bundleMarker(stackRoot, ""))
	return err == nil
}

// bundleMarker is where the last-extracted digest for a destination is recorded, kept OUT of the
// served web root so it is never exposed. "root" stands in for the host bundle's empty path.
func bundleMarker(stackRoot, path string) string {
	slug := "root"
	if path != "" {
		slug = strings.ReplaceAll(strings.Trim(path, "/"), "/", "_")
	}
	return filepath.Join(stackRoot, "www", ".markers", slug+".digest")
}

// newBundleRepo builds an authenticated ORAS repository for artifact, reusing the same host Docker
// credentials image pulls use, and returns the tag/digest reference to resolve.
func newBundleRepo(artifact string) (*remote.Repository, string, error) {
	repoRef, reference := splitReference(artifact)
	repo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, "", err
	}
	host, user, pass := dockerx.RegistryCredential(artifact)
	if user != "" || pass != "" {
		repo.Client = &auth.Client{
			Client:     retry.DefaultClient,
			Cache:      auth.NewCache(),
			Credential: auth.StaticCredential(host, auth.Credential{Username: user, Password: pass}),
		}
	}
	return repo, reference, nil
}

// splitReference separates a repository from its tag or digest. A digest (@sha256:...) wins; else the
// last colon after the final path segment is the tag; else "latest". Registry ports (host:5000/...)
// are not mistaken for tags because their colon precedes the last slash.
func splitReference(ref string) (repo, reference string) {
	if at := strings.Index(ref, "@"); at >= 0 {
		return ref[:at], ref[at+1:]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, "latest"
}

// findTarball returns the single packed bundle (web.tar.gz) restored by the file store, matching by
// suffix rather than an exact name so a differently-named bundle still resolves.
func findTarball(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && (strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")) {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf("no .tar.gz bundle in pulled artifact")
}

// extractTarGz unpacks a gzipped tar into dest, creating it if needed and rejecting any entry that
// would escape dest (zip-slip). The archive is a trusted, maintainer-built bundle from GHCR.
func extractTarGz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	cleanDest := filepath.Clean(dest)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(cleanDest, hdr.Name)
		if target != cleanDest && !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode&0o777))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}
