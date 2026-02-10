package admission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/kubewarden/sbomscanner/api"
	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

func TestWorkloadScanReportValidation_Validate(t *testing.T) {
	const (
		serviceAccountNamespace = "sbomscanner"
		serviceAccountName      = "sbomscanner-controller"
	)

	allowedUser := &user.DefaultInfo{
		Name: "system:serviceaccount:sbomscanner:sbomscanner-controller",
	}
	forbiddenUser := &user.DefaultInfo{
		Name: "system:serviceaccount:default:other",
	}

	managedReport := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-report",
			Namespace: "default",
			Labels: map[string]string{
				api.LabelManagedByKey: api.LabelManagedByValue,
			},
		},
	}

	unmanagedReport := &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-report",
			Namespace: "default",
			Labels: map[string]string{
				api.LabelManagedByKey: "something-else",
			},
		},
	}

	gvk := storagev1alpha1.SchemeGroupVersion.WithKind("WorkloadScanReport")
	gvr := storagev1alpha1.SchemeGroupVersion.WithResource("workloadscanreports")

	tests := []struct {
		name        string
		operation   admission.Operation
		object      runtime.Object
		oldObject   runtime.Object
		userInfo    user.Info
		expectError bool
	}{
		{
			name:        "Create managed report with allowed user",
			operation:   admission.Create,
			object:      managedReport,
			userInfo:    allowedUser,
			expectError: false,
		},
		{
			name:        "Create managed report with forbidden user",
			operation:   admission.Create,
			object:      managedReport,
			userInfo:    forbiddenUser,
			expectError: true,
		},
		{
			name:        "Create unmanaged report with forbidden user",
			operation:   admission.Create,
			object:      unmanagedReport,
			userInfo:    forbiddenUser,
			expectError: false,
		},
		{
			name:        "Update managed report with allowed user",
			operation:   admission.Update,
			object:      managedReport,
			oldObject:   managedReport,
			userInfo:    allowedUser,
			expectError: false,
		},
		{
			name:        "Update managed report with forbidden user",
			operation:   admission.Update,
			object:      managedReport,
			oldObject:   managedReport,
			userInfo:    forbiddenUser,
			expectError: true,
		},
		{
			name:        "Update unmanaged report with forbidden user",
			operation:   admission.Update,
			object:      unmanagedReport,
			oldObject:   unmanagedReport,
			userInfo:    forbiddenUser,
			expectError: false,
		},
		{
			name:        "Update removes managed label - should still be forbidden",
			operation:   admission.Update,
			object:      unmanagedReport,
			oldObject:   managedReport,
			userInfo:    forbiddenUser,
			expectError: true,
		},
		{
			name:        "Delete managed report with allowed user",
			operation:   admission.Delete,
			oldObject:   managedReport,
			userInfo:    allowedUser,
			expectError: false,
		},
		{
			name:        "Delete managed report with forbidden user",
			operation:   admission.Delete,
			oldObject:   managedReport,
			userInfo:    forbiddenUser,
			expectError: true,
		},
		{
			name:        "Delete unmanaged report with forbidden user",
			operation:   admission.Delete,
			oldObject:   unmanagedReport,
			userInfo:    forbiddenUser,
			expectError: false,
		},
		{
			name:        "Connect operation is always allowed",
			operation:   admission.Connect,
			userInfo:    forbiddenUser,
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := NewWorkloadScanReportValidation(serviceAccountNamespace, serviceAccountName)

			attrs := admission.NewAttributesRecord(
				test.object,
				test.oldObject,
				gvk,
				"default",
				"test-report",
				gvr,
				"",
				test.operation,
				nil,
				false,
				test.userInfo,
			)

			err := validator.Validate(context.Background(), attrs, nil)

			if test.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "forbidden")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
