package v1alpha1

// ConditionedJob is a job that reports its lifecycle through conditions.
// +k8s:deepcopy-gen=false
type ConditionedJob interface {
	IsScheduled() bool
	IsInProgress() bool
	IsComplete() bool
	IsFailed() bool
}
