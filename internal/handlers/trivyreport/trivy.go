package trivyreport

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	trivyDBTypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivyFanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

// NewResultsFromTrivyReport converts the results obtained by the Trivy scan,
// into the SBOMscanner VulnerabilityReport format.
func NewResultsFromTrivyReport(reportResults trivyTypes.Report) ([]storagev1alpha1.Result, error) {
	results := []storagev1alpha1.Result{}

	for _, trivyRes := range reportResults.Results {
		result := newResult(trivyRes)

		// vulnerabilities not suppressed by VEX
		for _, trivyVuln := range trivyRes.Vulnerabilities {
			vuln := newVulnerability(trivyVuln)
			vuln.Suppressed = false

			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}

		// vulnerabilities suppressed by VEX
		for _, trivyVuln := range trivyRes.ModifiedFindings {
			// skipping when Finding is not of type Vulnerability
			if trivyVuln.Type != trivyTypes.FindingTypeVulnerability {
				continue
			}

			suppressedVuln, err := decodeTrivyFinding(trivyVuln)
			if err != nil {
				return nil, fmt.Errorf("error reding trivy findings: %w", err)
			}

			vuln := newVulnerability(suppressedVuln)
			vuln.Suppressed = true
			vuln.VEXStatus = newVEXStatus(trivyVuln)

			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}

		results = append(results, result)
	}

	return results, nil
}

func newResult(trivyRes trivyTypes.Result) storagev1alpha1.Result {
	class := storagev1alpha1.Class(trivyRes.Class)

	// if Type indicates a compiled language
	// we categorize its Class as BinaryClass
	if trivyRes.Type == trivyFanalTypes.GoBinary ||
		trivyRes.Type == trivyFanalTypes.RustBinary {
		class = storagev1alpha1.ClassBinary
	}

	return storagev1alpha1.Result{
		Target: trivyRes.Target,
		Class:  class,
		Type:   string(trivyRes.Type),
	}
}

// newVulnerability sets the common vulnerability values from trivy
func newVulnerability(trivyVuln trivyTypes.DetectedVulnerability) storagev1alpha1.Vulnerability {
	return storagev1alpha1.Vulnerability{
		CVE:              trivyVuln.VulnerabilityID,
		Title:            trivyVuln.Title,
		PackageName:      trivyVuln.PkgName,
		PackagePath:      fixPath(trivyVuln.PkgPath),
		PURL:             trivyVuln.PkgIdentifier.PURL.String(),
		InstalledVersion: trivyVuln.InstalledVersion,
		FixedVersions:    getFixedVersions(trivyVuln.FixedVersion),
		DiffID:           trivyVuln.Layer.DiffID,
		Description:      trivyVuln.Description,
		Severity:         trivyVuln.Severity,
		References:       trivyVuln.References,
		CVSS:             newCVSS(trivyVuln.CVSS),
		CWEs:             trivyVuln.CweIDs,
	}
}

func decodeTrivyFinding(trivyVuln trivyTypes.ModifiedFinding) (trivyTypes.DetectedVulnerability, error) {
	// converting Finding into bytes data,
	// this because the field is private
	// so we cannot access its content directly:
	// https://github.com/aquasecurity/trivy/blob/v0.65.0/pkg/types/finding.go#L42
	finding := bytes.Buffer{}
	encoder := gob.NewEncoder(&finding)
	err := encoder.Encode(trivyVuln.Finding)
	if err != nil {
		return trivyTypes.DetectedVulnerability{}, fmt.Errorf("unable to encode finding: %w", err)
	}

	// decoding data into DetectedVulnerability type
	suppressedVuln := trivyTypes.DetectedVulnerability{}
	decoder := gob.NewDecoder(&finding)
	err = decoder.Decode(&suppressedVuln)
	if err != nil {
		return trivyTypes.DetectedVulnerability{}, fmt.Errorf("unable to decode finding: %w", err)
	}

	return suppressedVuln, nil
}

func newCVSS(trivyCVSS trivyDBTypes.VendorCVSS) map[string]storagev1alpha1.CVSS {
	cvssMap := make(map[string]storagev1alpha1.CVSS, len(trivyCVSS))
	for sid, cvss := range trivyCVSS {
		cvssMap[string(sid)] = storagev1alpha1.CVSS{
			V3Score:  strconv.FormatFloat(cvss.V3Score, 'f', -1, 64),
			V3Vector: cvss.V3Vector,
		}
	}
	return cvssMap
}

func newVEXStatus(trivyVEXStat trivyTypes.ModifiedFinding) *storagev1alpha1.VEXStatus {
	return &storagev1alpha1.VEXStatus{
		Repository: extractURLRegex(trivyVEXStat.Source),
		Status:     string(trivyVEXStat.Status),
		Statement:  trivyVEXStat.Statement,
	}
}

func extractURLRegex(input string) string {
	// Regex to match common URL patterns
	re := regexp.MustCompile(`https?://[^\s)]+`)
	return re.FindString(input)
}

func fixPath(inputPath string) string {
	if inputPath == "" {
		return ""
	}
	return path.Join("/", inputPath)
}

func getFixedVersions(input string) []string {
	if input == "" {
		return []string{}
	}
	return strings.Split(input, ", ")
}
