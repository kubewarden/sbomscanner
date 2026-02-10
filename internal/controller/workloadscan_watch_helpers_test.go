package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	v1alpha1 "github.com/kubewarden/sbomscanner/api/v1alpha1"
)

func TestMapObjToNamespace(t *testing.T) {
	tests := []struct {
		name              string
		object            client.Object
		expectedNamespace string
	}{
		{
			name: "pod in default namespace",
			object: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
			},
			expectedNamespace: "default",
		},
		{
			name: "pod in custom namespace",
			object: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "my-namespace",
				},
			},
			expectedNamespace: "my-namespace",
		},
		{
			name: "registry in sbomscanner namespace",
			object: &v1alpha1.Registry{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-registry",
					Namespace: "sbomscanner",
				},
			},
			expectedNamespace: "sbomscanner",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := mapObjToNamespace(context.Background(), test.object)

			require.Len(t, requests, 1)
			assert.Equal(t, test.expectedNamespace, requests[0].Namespace)
			assert.Empty(t, requests[0].Name, "Name should be empty for namespace-level reconciliation")
		})
	}
}

func TestMapNamespace(t *testing.T) {
	tests := []struct {
		name              string
		namespace         *corev1.Namespace
		expectedNamespace string
	}{
		{
			name: "default namespace",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
			},
			expectedNamespace: "default",
		},
		{
			name: "custom namespace",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-namespace",
				},
			},
			expectedNamespace: "my-namespace",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := mapNamespace(context.Background(), test.namespace)

			require.Len(t, requests, 1)
			assert.Equal(t, test.expectedNamespace, requests[0].Namespace)
			assert.Empty(t, requests[0].Name, "Name should be empty for namespace-level reconciliation")
		})
	}
}

func TestMapConfigToNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	tests := []struct {
		name               string
		configuration      *v1alpha1.WorkloadScanConfiguration
		namespaces         []corev1.Namespace
		expectedNamespaces []string
	}{
		{
			name: "selector is not specified matches all namespaces",
			configuration: &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					NamespaceSelector: nil,
				},
			},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-one"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-two"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-three"}},
			},
			expectedNamespaces: []string{"namespace-one", "namespace-two", "namespace-three"},
		},
		{
			name: "selector matches subset of namespaces",
			configuration: &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"scan": "enabled",
						},
					},
				},
			},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-one", Labels: map[string]string{"scan": "enabled"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-two", Labels: map[string]string{"scan": "disabled"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-three", Labels: map[string]string{"scan": "enabled"}}},
			},
			expectedNamespaces: []string{"namespace-one", "namespace-three"},
		},
		{
			name: "selector matches no namespaces",
			configuration: &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"nonexistent": "label",
						},
					},
				},
			},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-one"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-two"}},
			},
			expectedNamespaces: []string{},
		},
		{
			name: "selector with match expressions",
			configuration: &v1alpha1.WorkloadScanConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: v1alpha1.WorkloadScanConfigurationName,
				},
				Spec: v1alpha1.WorkloadScanConfigurationSpec{
					NamespaceSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "environment",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"production", "staging"},
							},
						},
					},
				},
			},
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-production", Labels: map[string]string{"environment": "production"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-staging", Labels: map[string]string{"environment": "staging"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "namespace-development", Labels: map[string]string{"environment": "development"}}},
			},
			expectedNamespaces: []string{"namespace-production", "namespace-staging"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			objects := make([]client.Object, 0, len(test.namespaces))
			for index := range test.namespaces {
				objects = append(objects, &test.namespaces[index])
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			mapFunction := mapConfigToNamespaces(fakeClient)
			requests := mapFunction(context.Background(), test.configuration)

			actualNamespaces := make([]string, 0, len(requests))
			for _, request := range requests {
				actualNamespaces = append(actualNamespaces, request.Namespace)
			}

			assert.ElementsMatch(t, test.expectedNamespaces, actualNamespaces)
		})
	}
}

func TestMapConfigToNamespaces_InvalidObject(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mapFunction := mapConfigToNamespaces(fakeClient)

	// Pass a non-WorkloadScanConfiguration object
	requests := mapFunction(context.Background(), &corev1.Pod{})

	assert.Nil(t, requests)
}

func TestPodImagesChangedPredicate_CreateEvent(t *testing.T) {
	predicate := podImagesChangedPredicate()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx:1.19"},
			},
		},
	}

	result := predicate.Create(event.CreateEvent{Object: pod})
	assert.True(t, result, "Create events should always return true")
}

func TestPodImagesChangedPredicate_DeleteEvent(t *testing.T) {
	predicate := podImagesChangedPredicate()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx:1.19"},
			},
		},
	}

	result := predicate.Delete(event.DeleteEvent{Object: pod})
	assert.True(t, result, "Delete events should always return true")
}

func TestPodImagesChangedPredicate_UpdateEvent(t *testing.T) {
	predicate := podImagesChangedPredicate()

	tests := []struct {
		name     string
		oldPod   *corev1.Pod
		newPod   *corev1.Pod
		expected bool
	}{
		{
			name: "no change in images",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			expected: false,
		},
		{
			name: "image tag changed",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.20"},
					},
				},
			},
			expected: true,
		},
		{
			name: "container added",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
						{Name: "sidecar", Image: "envoy:latest"},
					},
				},
			},
			expected: true,
		},
		{
			name: "container removed",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
						{Name: "sidecar", Image: "envoy:latest"},
					},
				},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			expected: true,
		},
		{
			name: "init container changed",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{Name: "init", Image: "busybox:1.0"},
					},
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{Name: "init", Image: "busybox:2.0"},
					},
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			expected: true,
		},
		{
			name: "only labels changed",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"version": "v1"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"version": "v2"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			expected: false,
		},
		{
			name: "only annotations changed",
			oldPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"note": "old"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"note": "new"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "nginx:1.19"},
					},
				},
			},
			expected: false,
		},
		{
			name: "image registry changed",
			oldPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "docker.io/nginx:1.19"},
					},
				},
			},
			newPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "app", Image: "ghcr.io/nginx:1.19"},
					},
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateEvent := event.UpdateEvent{
				ObjectOld: test.oldPod,
				ObjectNew: test.newPod,
			}
			result := predicate.Update(updateEvent)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestPodImagesChangedPredicate_UpdateEvent_InvalidObjects(t *testing.T) {
	predicate := podImagesChangedPredicate()

	tests := []struct {
		name      string
		objectOld client.Object
		objectNew client.Object
	}{
		{
			name:      "old object is not a pod",
			objectOld: &corev1.Namespace{},
			objectNew: &corev1.Pod{},
		},
		{
			name:      "new object is not a pod",
			objectOld: &corev1.Pod{},
			objectNew: &corev1.Namespace{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateEvent := event.UpdateEvent{
				ObjectOld: test.objectOld,
				ObjectNew: test.objectNew,
			}
			result := predicate.Update(updateEvent)
			assert.False(t, result)
		})
	}
}

func TestExtractImagesFromPodSpec(t *testing.T) {
	tests := []struct {
		name     string
		podSpec  corev1.PodSpec
		expected []string
	}{
		{
			name: "single container",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:1.19"},
				},
			},
			expected: []string{"nginx:1.19"},
		},
		{
			name: "multiple containers",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:1.19"},
					{Name: "sidecar", Image: "envoy:latest"},
				},
			},
			expected: []string{"nginx:1.19", "envoy:latest"},
		},
		{
			name: "init containers only",
			podSpec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "init-one", Image: "busybox:1.0"},
					{Name: "init-two", Image: "alpine:3.14"},
				},
			},
			expected: []string{"busybox:1.0", "alpine:3.14"},
		},
		{
			name: "init and regular containers",
			podSpec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "init", Image: "busybox:1.0"},
				},
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:1.19"},
				},
			},
			expected: []string{"busybox:1.0", "nginx:1.19"},
		},
		{
			name:     "empty pod spec",
			podSpec:  corev1.PodSpec{},
			expected: []string{},
		},
		{
			name: "multiple init and regular containers",
			podSpec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "init-one", Image: "busybox:1.0"},
					{Name: "init-two", Image: "alpine:3.14"},
				},
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:1.19"},
					{Name: "sidecar", Image: "envoy:latest"},
				},
			},
			expected: []string{"busybox:1.0", "alpine:3.14", "nginx:1.19", "envoy:latest"},
		},
		{
			name: "preserves order with init containers first",
			podSpec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "init", Image: "init-image:v1"},
				},
				Containers: []corev1.Container{
					{Name: "app", Image: "app-image:v1"},
				},
			},
			expected: []string{"init-image:v1", "app-image:v1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := extractImagesFromPodSpec(test.podSpec)
			assert.Equal(t, test.expected, result)
		})
	}
}
