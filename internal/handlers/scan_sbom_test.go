package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
	"github.com/kubewarden/sbomscanner/api/v1alpha1"
	"github.com/kubewarden/sbomscanner/pkg/generated/clientset/versioned/scheme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	_ "modernc.org/sqlite"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestScanSBOMHandler_Handle(t *testing.T) {
	vexHubServer := fakeVEXHubRepository(t)
	vexHubServer.Start()
	defer vexHubServer.Close()

	cacheDir := t.TempDir()

	for _, test := range []struct {
		platform           string
		vexHubList         []v1alpha1.VEXHub
		sourceSBOMJSON     string
		expectedReportJSON string
	}{
		{
			platform:           "linux/amd64",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.sbomscanner.json"),
		},
		{
			platform:           "linux/arm/v6",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-arm-v6.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-arm-v6.sbomscanner.json"),
		},
		{
			platform:           "linux/arm/v7",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-arm-v7.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-arm-v7.sbomscanner.json"),
		},
		{
			platform:           "linux/arm64/v8",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-arm64-v8.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-arm64-v8.sbomscanner.json"),
		},
		{
			platform:           "linux/386",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-386.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-386.sbomscanner.json"),
		},
		{
			platform:           "linux/ppc64le",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-ppc64le.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-ppc64le.sbomscanner.json"),
		},
		{
			platform:           "linux/s390x",
			vexHubList:         []v1alpha1.VEXHub{},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-s390x.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-s390x.sbomscanner.json"),
		},
		{
			platform: "linux/s390x with VEX repo enabled",
			vexHubList: []v1alpha1.VEXHub{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
					Spec: v1alpha1.VEXHubSpec{
						URL:     vexHubServer.URL,
						Enabled: true,
					},
				},
			},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.sbomscanner-vex.json"),
		},
		{
			platform: "linux/s390x with VEX repo not enabled",
			vexHubList: []v1alpha1.VEXHub{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
					Spec: v1alpha1.VEXHubSpec{
						URL:     vexHubServer.URL,
						Enabled: false,
					},
				},
			},
			sourceSBOMJSON:     filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.spdx.json"),
			expectedReportJSON: filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.sbomscanner.json"),
		},
	} {
		t.Run(test.platform, func(t *testing.T) {
			testScanSBOM(t, cacheDir, test.platform, test.sourceSBOMJSON, test.expectedReportJSON, test.vexHubList)
		})
	}
}

func testScanSBOM(t *testing.T, cacheDir, platform, sourceSBOMJSON, expectedReportJSON string, vexHubList []v1alpha1.VEXHub) {
	spdxData, err := os.ReadFile(sourceSBOMJSON)
	require.NoError(t, err, "failed to read source SBOM file %s", sourceSBOMJSON)

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: "test-registry",
		},
	}

	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sbom",
			Namespace: "default",
		},
		SPDX: runtime.RawExtension{Raw: spdxData},
	}
	vexHubs := &v1alpha1.VEXHubList{
		Items: vexHubList,
	}

	scheme := scheme.Scheme
	err = storagev1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(scanJob).
		WithRuntimeObjects(sbom).
		WithRuntimeObjects(vexHubs).
		Build()

	reportData, err := os.ReadFile(expectedReportJSON)
	require.NoError(t, err, "failed to read expected report file %s", expectedReportJSON)

	expectedReport := &storagev1alpha1.Report{}
	err = json.Unmarshal(reportData, expectedReport)
	require.NoError(t, err, "failed to unmarshal expected report file %s", expectedReportJSON)

	handler := NewScanSBOMHandler(k8sClient, scheme, cacheDir, testTrivyDBRepository, testTrivyJavaDBRepository, slog.Default())

	message, err := json.Marshal(&ScanSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		SBOM: ObjectRef{
			Name:      sbom.Name,
			Namespace: sbom.Namespace,
		},
	})
	require.NoError(t, err)

	err = handler.Handle(t.Context(), &testMessage{data: message})
	require.NoError(t, err, "failed to scan SBOM, with platform %s", platform)

	vulnerabilityReport := &storagev1alpha1.VulnerabilityReport{}
	err = k8sClient.Get(t.Context(), client.ObjectKey{
		Name:      sbom.Name,
		Namespace: sbom.Namespace,
	}, vulnerabilityReport)
	require.NoError(t, err, "failed to get vulnerability report, with platform %s", platform)

	assert.Equal(t, sbom.GetImageMetadata(), vulnerabilityReport.GetImageMetadata())
	assert.Equal(t, sbom.UID, vulnerabilityReport.GetOwnerReferences()[0].UID)
	assert.Equal(t, string(scanJob.UID), vulnerabilityReport.Labels[v1alpha1.LabelScanJobUIDKey])

	report := &vulnerabilityReport.Report
	require.NotEmpty(t, report)

	// override report field since trivy uses the sbom name as Target,
	// which changes at every test run.
	report.Results[0].Target = expectedReport.Results[0].Target
	assert.Equal(t, expectedReport, report)
}

func fakeVEXHubRepository(t *testing.T) *httptest.Server {
	handler := http.FileServer(http.Dir("../../test/fixtures/vexhub"))
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp", "127.0.0.1:1337")
	require.NoError(t, err)
	server.Listener = listener
	return server
}

func TestScanSBOMHandler_Handle_StopProcessing(t *testing.T) {
	spdxData, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "golang-1.12-alpine-amd64.spdx.json"))
	require.NoError(t, err)
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sbom",
			Namespace: "default",
		},
		SPDX: runtime.RawExtension{Raw: spdxData},
	}

	vexHubs := &v1alpha1.VEXHubList{
		Items: []v1alpha1.VEXHub{},
	}

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
		},
		Spec: v1alpha1.ScanJobSpec{
			Registry: "test-registry",
		},
	}

	differentUIDScanJob := scanJob.DeepCopy()
	differentUIDScanJob.UID = "test-scanjob-different-uid"

	failedScanJob := scanJob.DeepCopy()
	failedScanJob.MarkFailed(v1alpha1.ReasonInternalError, "kaboom")

	tests := []struct {
		name            string
		scanJob         *v1alpha1.ScanJob
		existingObjects []runtime.Object
	}{
		{
			name:            "scanjob not found",
			scanJob:         scanJob,
			existingObjects: []runtime.Object{sbom, vexHubs},
		},
		{
			name:            "scanjob was recreated with  different UID",
			scanJob:         scanJob,
			existingObjects: []runtime.Object{differentUIDScanJob, sbom, vexHubs},
		},
		{
			name:            "scanjob failed",
			scanJob:         failedScanJob,
			existingObjects: []runtime.Object{failedScanJob, sbom, vexHubs},
		},
		{
			name:            "sbom not found",
			scanJob:         scanJob,
			existingObjects: []runtime.Object{scanJob, vexHubs},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := scheme.Scheme
			err := storagev1alpha1.AddToScheme(scheme)
			require.NoError(t, err)
			err = v1alpha1.AddToScheme(scheme)
			require.NoError(t, err)

			k8sClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(test.existingObjects...).
				Build()

			cacheDir := t.TempDir()
			handler := NewScanSBOMHandler(k8sClient, scheme, cacheDir, testTrivyDBRepository, testTrivyJavaDBRepository, slog.Default())

			message, err := json.Marshal(&ScanSBOMMessage{
				BaseMessage: BaseMessage{
					ScanJob: ObjectRef{
						Name:      test.scanJob.Name,
						Namespace: test.scanJob.Namespace,
						UID:       string(test.scanJob.UID),
					},
				},
				SBOM: ObjectRef{
					Name:      sbom.Name,
					Namespace: sbom.Namespace,
				},
			})
			require.NoError(t, err)

			// Should return nil (no error) when resource doesn't exist
			err = handler.Handle(context.Background(), &testMessage{data: message})
			require.NoError(t, err)

			// Verify no VulnerabilityReport was created
			vulnerabilityReport := &storagev1alpha1.VulnerabilityReport{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{
				Name:      sbom.Name,
				Namespace: "default",
			}, vulnerabilityReport)
			assert.True(t, apierrors.IsNotFound(err), "VulnerabilityReport should not exist")
		})
	}
}

func TestShouldSkipScan(t *testing.T) {
	now := metav1.Now()
	oneHourAgo := metav1.NewTime(now.Add(-1 * time.Hour))
	twoHoursAgo := metav1.NewTime(now.Add(-2 * time.Hour))

	tests := []struct {
		name           string
		existingReport *storagev1alpha1.VulnerabilityReport
		workerVulnDB   metav1.Time
		workerJavaDB   metav1.Time
		shouldScan     bool
	}{
		{
			name: "database version is newer than the last one",
			existingReport: &storagev1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: oneHourAgo},
				ScannerDBVersion: map[string]metav1.Time{
					storagev1alpha1.ScannerTrivyDB:     twoHoursAgo,
					storagev1alpha1.ScannerTrivyJavaDB: twoHoursAgo,
				},
			},
			workerVulnDB: now,
			workerJavaDB: now,
			shouldScan:   true,
		},
		{
			name: "database version is older than the last one",
			existingReport: &storagev1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: oneHourAgo},
				ScannerDBVersion: map[string]metav1.Time{
					storagev1alpha1.ScannerTrivyDB:     now,
					storagev1alpha1.ScannerTrivyJavaDB: now,
				},
			},
			workerVulnDB: twoHoursAgo,
			workerJavaDB: twoHoursAgo,
			shouldScan:   false,
		},
		{
			name: "last database doesn't exist yet (first scan ever)",
			existingReport: &storagev1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.Time{}}, // Zero time
			},
			workerVulnDB: now,
			workerJavaDB: now,
			shouldScan:   true,
		},
		{
			name: "database versions are the same",
			existingReport: &storagev1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{CreationTimestamp: oneHourAgo},
				ScannerDBVersion: map[string]metav1.Time{
					storagev1alpha1.ScannerTrivyDB:     now,
					storagev1alpha1.ScannerTrivyJavaDB: now,
				},
			},
			workerVulnDB: now,
			workerJavaDB: now,
			shouldScan:   false,
		},
	}

	handler := &ScanSBOMHandler{} // Instance to call the method

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handler.shouldTrivyScan(tt.existingReport, tt.workerVulnDB, tt.workerJavaDB)

			if got != tt.shouldScan {
				t.Errorf("shoulTrivydScan() = %v, want %v", got, tt.shouldScan)
				t.Logf("Report DB: %v, Worker DB: %v",
					tt.existingReport.ScannerDBVersion[storagev1alpha1.ScannerTrivyDB],
					tt.workerVulnDB)
			}
		})
	}
}

// write an old version of the database -> update vulnerability report
func TestScanSBOMHandler_Handle_ConflictShouldNotUpdate(t *testing.T) {
	scheme := scheme.Scheme
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	now := metav1.Now()
	newer := metav1.NewTime(now.Add(1 * time.Hour))

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
		},
		Spec: v1alpha1.ScanJobSpec{Registry: "test-registry"},
	}
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sbom",
			Namespace: "default",
		},
		SPDX: runtime.RawExtension{Raw: []byte(`{"spdxVersion":"SPDX-2.2"}`)},
	}

	// Existing report with newer DB versions
	existingReport := &storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: now, Name: sbom.Name, Namespace: sbom.Namespace},
		ScannerDBVersion: map[string]metav1.Time{
			storagev1alpha1.ScannerTrivyDB:     newer,
			storagev1alpha1.ScannerTrivyJavaDB: newer,
		},
	}

	updateAttempts := 0

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(scanJob, sbom, existingReport).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				updateAttempts++
				if updateAttempts == 1 {
					return apierrors.NewConflict(
						schema.GroupResource{Group: "mygroup", Resource: "myresources"},
						obj.GetName(), nil)
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	handler := NewScanSBOMHandler(fakeClient, scheme, t.TempDir(), testTrivyDBRepository, testTrivyJavaDBRepository, slog.Default())

	message, err := json.Marshal(&ScanSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		SBOM: ObjectRef{
			Name:      sbom.Name,
			Namespace: sbom.Namespace,
		},
	})
	require.NoError(t, err)

	err = handler.Handle(context.Background(), &testMessage{data: message})
	require.NoError(t, err)

	// Should not update the report, DB versions should remain as in existingReport
	updated := &storagev1alpha1.VulnerabilityReport{}
	errGet := fakeClient.Get(context.Background(), client.ObjectKey{Name: sbom.Name, Namespace: sbom.Namespace}, updated)
	require.NoError(t, errGet)
	assert.Equal(t, newer, updated.ScannerDBVersion[storagev1alpha1.ScannerTrivyDB])
	assert.Equal(t, newer, updated.ScannerDBVersion[storagev1alpha1.ScannerTrivyJavaDB])
}

// write a new version of the database -> update vulnerability report
func TestScanSBOMHandler_Handle_ConflitShouldUpdate(t *testing.T) {
	scheme := scheme.Scheme
	require.NoError(t, storagev1alpha1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	now := metav1.Now()
	older := metav1.NewTime(now.Add(-1 * time.Hour))

	scanJob := &v1alpha1.ScanJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-scanjob",
			Namespace: "default",
			UID:       "test-scanjob-uid",
		},
		Spec: v1alpha1.ScanJobSpec{Registry: "test-registry"},
	}
	sbom := &storagev1alpha1.SBOM{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sbom",
			Namespace: "default",
		},
		SPDX: runtime.RawExtension{Raw: []byte(`{"spdxVersion":"SPDX-2.2"}`)},
	}

	// Existing report with older DB versions
	existingReport := &storagev1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: now, Name: sbom.Name, Namespace: sbom.Namespace},
		ScannerDBVersion: map[string]metav1.Time{
			storagev1alpha1.ScannerTrivyDB:     older,
			storagev1alpha1.ScannerTrivyJavaDB: older,
		},
	}

	updateAttempts := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(scanJob, sbom, existingReport).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				updateAttempts++
				if updateAttempts == 1 {
					return apierrors.NewConflict(
						schema.GroupResource{Group: "mygroup", Resource: "myresources"},
						obj.GetName(), nil)
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	handler := NewScanSBOMHandler(fakeClient, scheme, t.TempDir(), testTrivyDBRepository, testTrivyJavaDBRepository, slog.Default())

	message, err := json.Marshal(&ScanSBOMMessage{
		BaseMessage: BaseMessage{
			ScanJob: ObjectRef{
				Name:      scanJob.Name,
				Namespace: scanJob.Namespace,
				UID:       string(scanJob.UID),
			},
		},
		SBOM: ObjectRef{
			Name:      sbom.Name,
			Namespace: sbom.Namespace,
		},
	})
	require.NoError(t, err)

	err = handler.Handle(context.Background(), &testMessage{data: message})
	require.NoError(t, err)

	// Should update the report, DB versions should be updated to now
	updated := &storagev1alpha1.VulnerabilityReport{}
	errGet := fakeClient.Get(context.Background(), client.ObjectKey{Name: sbom.Name, Namespace: sbom.Namespace}, updated)
	require.NoError(t, errGet)
	assert.Equal(t, now, updated.ScannerDBVersion[storagev1alpha1.ScannerTrivyDB])
	assert.Equal(t, now, updated.ScannerDBVersion[storagev1alpha1.ScannerTrivyJavaDB])
}
