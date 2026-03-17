package handlers

const (
	GenerateSBOMSubject     = "sbomscanner.sbom.generate"
	ScanSBOMSubject         = "sbomscanner.sbom.scan"
	CreateCatalogSubject    = "sbomscanner.catalog.create"
	GenerateNodeSBOMSubject = "sbomscanner.nodesbom.generate"
	ScanNodeSBOMSubject     = "sbomscanner.nodesbom.scan"
)

// ObjectRef is a reference to a Kubernetes object, used in messages to identify resources.
// UID should be populated when you need to verify the exact resource instance
// (e.g., to detect if the resource was deleted and recreated).
type ObjectRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid,omitempty"`
}

// BaseMessage is the base structure for messages.
type BaseMessage struct {
	ScanJob ObjectRef `json:"scanjob"`
}

// CreateCatalogMessage represents a request to create a catalog of images in a registry.
type CreateCatalogMessage struct {
	BaseMessage
}

// GenerateSBOMMessage represents the request message for generating a SBOM.
type GenerateSBOMMessage struct {
	BaseMessage
	Image ObjectRef `json:"image"`
}

// ScanSBOMMessage represents the request message for scanning a SBOM.
type ScanSBOMMessage struct {
	BaseMessage
	SBOM ObjectRef `json:"sbom"`
}

// NodeBaseMessage is the base structure for node messages.
type NodeBaseMessage struct {
	NodeScanJob ObjectRef `json:"nodescanjob"`
}

// GenerateNodeSBOMMessage represents the request message for generating a node SBOM.
type GenerateNodeSBOMMessage struct {
	NodeBaseMessage
	Node ObjectRef `json:"node"`
}

// ScanNodeSBOMMessage represents the request message for scanning a node SBOM.
type ScanNodeSBOMMessage struct {
	NodeBaseMessage
	NodeSBOM ObjectRef `json:"nodesbom"`
}
