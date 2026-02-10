package admission

import (
	"context"
	"errors"
	"fmt"
	"io"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

const PluginNameWorkloadScanReportValidation = "WorkloadScanReportValidation"

type WorkloadScanReportValidation struct {
	*admission.Handler
	serviceAccountNamespace string
	serviceAccountName      string
}

func NewWorkloadScanReportValidation(serviceAccountNamespace, serviceAccountName string) *WorkloadScanReportValidation {
	return &WorkloadScanReportValidation{
		Handler:                 admission.NewHandler(admission.Create, admission.Update, admission.Delete),
		serviceAccountNamespace: serviceAccountNamespace,
		serviceAccountName:      serviceAccountName,
	}
}

func (v *WorkloadScanReportValidation) Register(plugins *admission.Plugins) {
	plugins.Register(PluginNameWorkloadScanReportValidation, func(_ io.Reader) (admission.Interface, error) {
		return v, nil
	})
}

func (v *WorkloadScanReportValidation) GetName() string {
	return PluginNameWorkloadScanReportValidation
}

var _ admission.ValidationInterface = &WorkloadScanReportValidation{}

func (v *WorkloadScanReportValidation) Validate(_ context.Context, attrs admission.Attributes, _ admission.ObjectInterfaces) error {
	if attrs.GetKind().GroupKind() != storagev1alpha1.SchemeGroupVersion.WithKind("WorkloadScanReport").GroupKind() {
		return nil
	}

	var report *storagev1alpha1.WorkloadScanReport

	switch attrs.GetOperation() {
	case admission.Create:
		obj := attrs.GetObject()
		if obj == nil {
			return nil
		}
		var ok bool
		report, ok = obj.(*storagev1alpha1.WorkloadScanReport)
		if !ok {
			return nil
		}
	case admission.Update, admission.Delete:
		oldObj := attrs.GetOldObject()
		if oldObj == nil {
			return nil
		}
		var ok bool
		report, ok = oldObj.(*storagev1alpha1.WorkloadScanReport)
		if !ok {
			return nil
		}
	case admission.Connect:
		return nil
	}

	if err := v.validateManagedWorkloadScanReport(attrs, report); err != nil {
		return err
	}

	return nil
}

// validateManagedWorkloadScanReport ensures that only the designated service account can modify managed WorkloadScanReport resources.
func (v *WorkloadScanReportValidation) validateManagedWorkloadScanReport(attrs admission.Attributes, report *storagev1alpha1.WorkloadScanReport) error {
	managedLabel := report.GetLabels()[api.LabelManagedByKey]
	if managedLabel != api.LabelManagedByValue {
		return nil
	}

	allowedUsername := fmt.Sprintf("system:serviceaccount:%s:%s", v.serviceAccountNamespace, v.serviceAccountName)
	if attrs.GetUserInfo().GetName() != allowedUsername {
		return apierrors.NewForbidden(
			schema.GroupResource{
				Group:    attrs.GetResource().Group,
				Resource: attrs.GetResource().Resource,
			},
			report.GetName(),
			errors.New("modifying managed resources of type WorkloadScanReport is forbidden"),
		)
	}

	return nil
}

func (v *WorkloadScanReportValidation) ValidateInitialization() error {
	return nil
}
