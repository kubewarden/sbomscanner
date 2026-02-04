package v1alpha1

// Summary provides a high-level overview of the vulnerabilities found.
type Summary struct {
	// Critical vulnerabilities count
	Critical int `json:"critical" protobuf:"varint,1,req,name=critical"`

	// High vulnerabilities count
	High int `json:"high" protobuf:"varint,2,req,name=high"`

	// Medium vulnerabilities count
	Medium int `json:"medium" protobuf:"varint,3,req,name=medium"`

	// Low vulnerabilities count
	Low int `json:"low" protobuf:"varint,4,req,name=low"`

	// Unknown vulnerabilities count
	Unknown int `json:"unknown" protobuf:"varint,5,req,name=unknown"`

	// Suppressed vulnerabilities count
	Suppressed int `json:"suppressed" protobuf:"varint,6,req,name=suppressed"`
}

func NewSummaryFromResults(results []Result) Summary {
	summary := Summary{}
	for _, result := range results {
		for _, vuln := range result.Vulnerabilities {
			summary.Add(vuln)
		}
	}

	return summary
}

func (s *Summary) Add(vulnerability Vulnerability) {
	if vulnerability.Suppressed {
		s.Suppressed++
		return
	}

	switch vulnerability.Severity {
	case "CRITICAL":
		s.Critical++
	case "HIGH":
		s.High++
	case "MEDIUM":
		s.Medium++
	case "LOW":
		s.Low++
	default:
		s.Unknown++
	}
}
