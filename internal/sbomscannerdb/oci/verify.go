package oci

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	gcrname "github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

// Hardcoded keyless trust policy for the officially published sbomscanner DB.
// The identity is matched by regexp so any branch or tag ref of the publishing
// workflow verifies. A later iteration replaces these constants with CRD/flag
// configuration (see docs/rfc/0010).
// TODO: pin the exact publishing workflow file name once CI signing lands.
const (
	dbCertOIDCIssuer     = "https://token.actions.githubusercontent.com"
	dbCertIdentityRegexp = `^https://github\.com/kubewarden/sbomscanner/\.github/workflows/.+@refs/.+$`
)

// ErrVerification is returned when the artifact fails signature verification.
var ErrVerification = errors.New("signature verification failed")

// Verifier checks that a DB artifact was signed by the trusted CI identity using
// cosign keyless (Fulcio + Rekor) signatures.
type Verifier struct {
	config Config
	logger *slog.Logger
}

// NewVerifier returns a Verifier that contacts the registry with the same TLS
// and plain-HTTP settings as the Remote.
func NewVerifier(config Config, logger *slog.Logger) *Verifier {
	return &Verifier{config: config, logger: logger}
}

// Verify checks the cosign signatures attached to the resolved digest of ref
// (never the mutable tag) against the hardcoded issuer and identity. It returns
// nil on a valid signature and a wrapped ErrVerification otherwise.
func (v *Verifier) Verify(ctx context.Context, ref, digest string) error {
	parsed, err := parseTagReference(ref)
	if err != nil {
		return err
	}
	// Pin the exact bytes: verify by digest so the signature covers the content
	// we are about to unpack, not whatever the tag points to now.
	digestRef := parsed.Registry + "/" + parsed.Repository + "@" + digest
	nameRef, err := gcrname.ParseReference(digestRef)
	if err != nil {
		return fmt.Errorf("parse digest reference %q: %w", digestRef, err)
	}

	checkOpts, err := v.checkOpts(ctx)
	if err != nil {
		return err
	}

	_, bundleVerified, err := cosign.VerifyImageSignatures(ctx, nameRef, checkOpts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerification, err)
	}
	if !bundleVerified {
		return fmt.Errorf("%w: transparency-log bundle not verified", ErrVerification)
	}
	v.logger.InfoContext(ctx, "sbomscanner DB signature verified", "digest", digest, "issuer", dbCertOIDCIssuer)
	return nil
}

// checkOpts assembles the cosign keyless verification policy: Fulcio roots plus
// Rekor and CT log keys (from the embedded TUF defaults), the hardcoded identity,
// and registry access mirroring the Remote's credentials and TLS settings.
func (v *Verifier) checkOpts(ctx context.Context) (*cosign.CheckOpts, error) {
	roots, err := fulcioroots.Get()
	if err != nil {
		return nil, fmt.Errorf("load fulcio roots: %w", err)
	}
	intermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, fmt.Errorf("load fulcio intermediates: %w", err)
	}
	rekorPubs, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("load rekor keys: %w", err)
	}
	ctPubs, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("load ct log keys: %w", err)
	}

	return &cosign.CheckOpts{
		RootCerts:          roots,
		IntermediateCerts:  intermediates,
		RekorPubKeys:       rekorPubs,
		CTLogPubKeys:       ctPubs,
		RegistryClientOpts: v.registryClientOpts(),
		Identities: []cosign.Identity{{
			Issuer:        dbCertOIDCIssuer,
			SubjectRegExp: dbCertIdentityRegexp,
		}},
	}, nil
}

// registryClientOpts builds the go-containerregistry options cosign uses to
// reach the registry, honoring the docker credentials store and the config's
// TLS and plain-HTTP settings.
func (v *Verifier) registryClientOpts() []ociremote.Option {
	remoteOpts := []gcrremote.Option{
		gcrremote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if v.config.SkipTLSVerify {
		transport := gcrremote.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in by --skip-tls-verify
		remoteOpts = append(remoteOpts, gcrremote.WithTransport(transport))
	}

	opts := []ociremote.Option{ociremote.WithRemoteOptions(remoteOpts...)}
	if v.config.PlainHTTP {
		opts = append(opts, ociremote.WithNameOptions(gcrname.Insecure))
	}
	return opts
}
