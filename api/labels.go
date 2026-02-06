package api

// Common labels used across the application

const (
	LabelManagedByKey      = "app.kubernetes.io/managed-by"
	LabelManagedByValue    = "sbomscanner"
	LabelPartOfKey         = "app.kubernetes.io/part-of"
	LabelPartOfValue       = "sbomscanner"
	LabelWorkloadScanKey   = "sbomscanner.kubwarden.io/workloadscan"
	LabelWorkloadScanValue = "true"
)
