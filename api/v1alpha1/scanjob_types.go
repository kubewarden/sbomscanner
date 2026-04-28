package v1alpha1

import (
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const LabelScanJobUIDKey = "sbomscanner.kubewarden.io/scanjob-uid"

const (
	// IndexScanJobSpecRegistry is the field index for the registry of a ScanJob.
	IndexScanJobSpecRegistry = "spec.registry"
	// IndexScanJobMetadataUID is the field index for the UID of a ScanJob.
	IndexScanJobMetadataUID = "metadata.uid"
)

// RegistryAnnotation stores a snapshot of the Registry targeted by the ScanJob.
const (
	// AnnotationScanJobRegistryKey stores a snapshot of the Registry targeted by the ScanJob.
	AnnotationScanJobRegistryKey = "sbomscanner.kubewarden.io/registry"
	// AnnotationScanJobCreationTimestampKey is used to store the creation timestamp of the ScanJob.
	AnnotationScanJobCreationTimestampKey = "sbomscanner.kubewarden.io/creation-timestamp"
	// AnnotationScanJobTriggerKey is used to identify the source of the ScanJob trigger.
	AnnotationScanJobTriggerKey = "sbomscanner.kubewarden.io/trigger"
)

const (
	ConditionTypeScheduled  = "Scheduled"
	ConditionTypeInProgress = "InProgress"
	ConditionTypeComplete   = "Complete"
	ConditionTypeFailed     = "Failed"
)

const (
	ReasonPending                   = "Pending"
	ReasonScheduled                 = "Scheduled"
	ReasonInProgress                = "InProgress"
	ReasonCatalogCreationInProgress = "CatalogCreationInProgress"
	ReasonSBOMGenerationInProgress  = "SBOMGenerationInProgress"
	ReasonImageScanInProgress       = "ImageScanInProgress"
	ReasonComplete                  = "Complete"
	ReasonFailed                    = "Failed"
	ReasonNoImagesToScan            = "NoImagesToScan"
	ReasonAllImagesScanned          = "AllImagesScanned"
	ReasonRegistryNotFound          = "RegistryNotFound"
	ReasonInternalError             = "InternalError"
)

const (
	messagePending    = "ScanJob is pending"
	messageScheduled  = "ScanJob is scheduled"
	messageInProgress = "ScanJob is in progress"
	messageCompleted  = "ScanJob completed successfully"
	messageFailed     = "ScanJob failed"
)

// ScanJobSpec defines the desired state of ScanJob.
type ScanJobSpec struct {
	// Registry is the registry in the same namespace to scan.
	// +kubebuilder:validation:Required
	Registry string `json:"registry"`
}

// ScanJobStatus defines the observed state of ScanJob.
type ScanJobStatus struct {
	// Conditions represent the latest available observations of ScanJob state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ImagesCount is the number of images in the registry.
	ImagesCount int `json:"imagesCount,omitempty"`

	// ScannedImagesCount is the number of images that have been scanned.
	ScannedImagesCount int `json:"scannedImagesCount,omitempty"`

	// StartTime is when the job started processing.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the job completed or failed.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=`.spec.registry`
// +kubebuilder:printcolumn:name="Registry",type="string",JSONPath=".spec.registry",description="Target registry"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.status=='True')].type",description="Current status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.status=='True')].reason",description="Status reason"
// +kubebuilder:printcolumn:name="Scanned",type="integer",JSONPath=".status.scannedImagesCount"
// +kubebuilder:printcolumn:name="Total",type="integer",JSONPath=".status.imagesCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ScanJob is the Schema for the scanjobs API.
type ScanJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScanJobSpec   `json:"spec,omitempty"`
	Status ScanJobStatus `json:"status,omitempty"`
}

// GetCreationTimestampFromAnnotation returns the creation timestamp of the ScanJob.
// It first attempts to parse the timestamp from the CreationTimestampAnnotation.
// If the annotation is missing or malformed, it falls back to the Kubernetes object's
// standard metadata.CreationTimestamp.
func (s *ScanJob) GetCreationTimestampFromAnnotation() time.Time {
	if timestampStr, ok := s.Annotations[AnnotationScanJobCreationTimestampKey]; ok {
		if timestamp, err := time.Parse(time.RFC3339Nano, timestampStr); err == nil {
			return timestamp
		}
	}

	return s.CreationTimestamp.Time
}

// InitializeConditions initializes status fields and conditions.
func (s *ScanJob) InitializeConditions() {
	s.Status.Conditions = []metav1.Condition{}

	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeScheduled,
		Status:             metav1.ConditionUnknown,
		Reason:             ReasonPending,
		Message:            messagePending,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeInProgress,
		Status:             metav1.ConditionUnknown,
		Reason:             ReasonPending,
		Message:            messagePending,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeComplete,
		Status:             metav1.ConditionUnknown,
		Reason:             ReasonPending,
		Message:            messagePending,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeFailed,
		Status:             metav1.ConditionUnknown,
		Reason:             ReasonPending,
		Message:            messagePending,
		ObservedGeneration: s.Generation,
	})
}

// MarkScheduled marks the job as scheduled.
func (s *ScanJob) MarkScheduled(reason, message string) {
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeScheduled,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeInProgress,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonScheduled,
		Message:            messageScheduled,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeComplete,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonScheduled,
		Message:            messageScheduled,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeFailed,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonScheduled,
		Message:            messageScheduled,
		ObservedGeneration: s.Generation,
	})
}

// MarkInProgress marks the job as in progress.
func (s *ScanJob) MarkInProgress(reason, message string) {
	now := metav1.Now()
	s.Status.StartTime = &now

	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeScheduled,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonInProgress,
		Message:            messageInProgress,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeInProgress,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeComplete,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonInProgress,
		Message:            messageInProgress,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeFailed,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonInProgress,
		Message:            messageInProgress,
		ObservedGeneration: s.Generation,
	})
}

// MarkComplete marks the job as complete.
func (s *ScanJob) MarkComplete(reason, message string) {
	now := metav1.Now()
	s.Status.CompletionTime = &now

	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeScheduled,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonComplete,
		Message:            messageCompleted,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeInProgress,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonComplete,
		Message:            messageCompleted,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeComplete,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeFailed,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonComplete,
		Message:            messageCompleted,
		ObservedGeneration: s.Generation,
	})
}

// MarkFailed marks the job as failed.
func (s *ScanJob) MarkFailed(reason, message string) {
	now := metav1.Now()
	s.Status.CompletionTime = &now

	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeScheduled,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonFailed,
		Message:            messageFailed,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeInProgress,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonFailed,
		Message:            messageFailed,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeComplete,
		Status:             metav1.ConditionFalse,
		Reason:             ReasonFailed,
		Message:            messageFailed,
		ObservedGeneration: s.Generation,
	})
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeFailed,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: s.Generation,
	})
}

// IsPending returns true if the job is not in any other state.
func (s *ScanJob) IsPending() bool {
	return !s.IsScheduled() && !s.IsInProgress() && !s.IsComplete() && !s.IsFailed()
}

// IsScheduled returns true if the job is scheduled.
func (s *ScanJob) IsScheduled() bool {
	scheduledCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeScheduled)
	if scheduledCond == nil {
		return false
	}
	return scheduledCond.Status == metav1.ConditionTrue
}

// IsInProgress returns true if the job is currently in progress.
func (s *ScanJob) IsInProgress() bool {
	inProgressCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeInProgress)
	if inProgressCond == nil {
		return false
	}
	return inProgressCond.Status == metav1.ConditionTrue
}

// IsComplete returns true if the job has completed successfully.
func (s *ScanJob) IsComplete() bool {
	completeCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeComplete)
	if completeCond == nil {
		return false
	}
	return completeCond.Status == metav1.ConditionTrue
}

// IsFailed returns true if the job has failed.
func (s *ScanJob) IsFailed() bool {
	failedCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeFailed)
	if failedCond == nil {
		return false
	}
	return failedCond.Status == metav1.ConditionTrue
}

// +kubebuilder:object:root=true

// ScanJobList contains a list of ScanJob.
type ScanJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanJob `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ScanJob{}, &ScanJobList{})
}
