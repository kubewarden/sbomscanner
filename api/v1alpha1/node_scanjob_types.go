package v1alpha1

import (
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const LabelNodeScanJobUIDKey = "sbomscanner.kubewarden.io/nodescanjob-uid"

const (
	// IndexNodeScanJobMetadataUID is the field index for the UID of a NodeScanJob.
	IndexNodeScanJobMetadataUID = "metadata.uid"
	// IndexNodeScanJobSpecNodeName is the field index for the node name of a NodeScanJob.
	IndexNodeScanJobSpecNodeName = "spec.nodeName"
)

// RegistryAnnotation stores a snapshot of the Registry targeted by the NodeScanJob.
const (
	// AnnotationNodeScanJobCreationTimestampKey is used to store the creation timestamp of the NodeScanJob.
	AnnotationNodeScanJobCreationTimestampKey = "sbomscanner.kubewarden.io/creation-timestamp"
	// AnnotationNodeScanJobTriggerKey is used to identify the source of the NodeScanJob trigger.
	AnnotationNodeScanJobTriggerKey = "sbomscanner.kubewarden.io/trigger"
)

const (
	ReasonNodeScanInProgress       = "NodeScanInProgress"
	ReasonNodeScanned              = "NodeScanned"
	ReasonScanAlreadyInProgress    = "ScanAlreadyInProgress"
)

// NodeScanJobSpec defines the desired state of NodeScanJob.
type NodeScanJobSpec struct {
	// NodeName specifies the name of the node to be scanned.
	NodeName string `json:"nodeName"`
}

// NodeScanJobStatus defines the observed state of NodeScanJob.
type NodeScanJobStatus struct {
	// Conditions represent the latest available observations of ScanJob state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// StartTime is when the job started processing.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the job completed or failed.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.status=='True')].type",description="Current status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.status=='True')].reason",description="Status reason"
// +kubebuilder:printcolumn:name="Scanned",type="integer",JSONPath=".status.scannedImagesCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// NodeScanJob is the Schema for the nodescanjobs API.
type NodeScanJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeScanJobSpec   `json:"spec,omitempty"`
	Status NodeScanJobStatus `json:"status,omitempty"`
}

// GetCreationTimestampFromAnnotation returns the creation timestamp of the NodeScanJob.
// It first attempts to parse the timestamp from the CreationTimestampAnnotation.
// If the annotation is missing or malformed, it falls back to the Kubernetes object's
// standard metadata.CreationTimestamp.
func (s *NodeScanJob) GetCreationTimestampFromAnnotation() time.Time {
	if timestampStr, ok := s.Annotations[AnnotationNodeScanJobCreationTimestampKey]; ok {
		if timestamp, err := time.Parse(time.RFC3339Nano, timestampStr); err == nil {
			return timestamp
		}
	}

	return s.CreationTimestamp.Time
}

// InitializeConditions initializes status fields and conditions.
func (s *NodeScanJob) InitializeConditions() {
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
func (s *NodeScanJob) MarkScheduled(reason, message string) {
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
func (s *NodeScanJob) MarkInProgress(reason, message string) {
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
func (s *NodeScanJob) MarkComplete(reason, message string) {
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
func (s *NodeScanJob) MarkFailed(reason, message string) {
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
func (s *NodeScanJob) IsPending() bool {
	return !s.IsScheduled() && !s.IsInProgress() && !s.IsComplete() && !s.IsFailed()
}

// IsScheduled returns true if the job is scheduled.
func (s *NodeScanJob) IsScheduled() bool {
	scheduledCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeScheduled)
	if scheduledCond == nil {
		return false
	}
	return scheduledCond.Status == metav1.ConditionTrue
}

// IsInProgress returns true if the job is currently in progress.
func (s *NodeScanJob) IsInProgress() bool {
	inProgressCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeInProgress)
	if inProgressCond == nil {
		return false
	}
	return inProgressCond.Status == metav1.ConditionTrue
}

// IsComplete returns true if the job has completed successfully.
func (s *NodeScanJob) IsComplete() bool {
	completeCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeComplete)
	if completeCond == nil {
		return false
	}
	return completeCond.Status == metav1.ConditionTrue
}

// IsFailed returns true if the job has failed.
func (s *NodeScanJob) IsFailed() bool {
	failedCond := meta.FindStatusCondition(s.Status.Conditions, ConditionTypeFailed)
	if failedCond == nil {
		return false
	}
	return failedCond.Status == metav1.ConditionTrue
}

// +kubebuilder:object:root=true

// NodeScanJobList contains a list of NodeScanJob.
type NodeScanJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeScanJob `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NodeScanJob{}, &NodeScanJobList{})
}
