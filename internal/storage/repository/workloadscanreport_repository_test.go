package repository

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

type workloadScanReportRepositoryTestSuite struct {
	suite.Suite
	pgContainer    *postgres.PostgresContainer
	db             *pgxpool.Pool
	repo           *WorkloadScanReportRepository
	imageRepo      *GenericObjectRepository
	vulnReportRepo *GenericObjectRepository
}

func TestWorkloadScanReportRepositoryTestSuite(t *testing.T) {
	suite.Run(t, &workloadScanReportRepositoryTestSuite{})
}

func (suite *workloadScanReportRepositoryTestSuite) SetupSuite() {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpassword"),
		postgres.BasicWaitStrategies(),
	)
	suite.Require().NoError(err, "failed to start postgres container")
	suite.pgContainer = pgContainer

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	suite.Require().NoError(err, "failed to get connection string")

	db, err := pgxpool.New(ctx, connStr)
	suite.Require().NoError(err, "failed to create connection pool")
	suite.db = db

	_, err = suite.db.Exec(ctx, `
		CREATE TABLE workloadscanreports (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			object JSONB NOT NULL,
			UNIQUE (name, namespace)
		);
		CREATE TABLE images (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			object JSONB NOT NULL,
			UNIQUE (name, namespace)
		);
		CREATE TABLE vulnerability_reports (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			object JSONB NOT NULL,
			UNIQUE (name, namespace)
		);
	`)
	suite.Require().NoError(err)

	suite.repo = NewWorkloadScanReportRepository("workloadscanreports", "vulnerability_reports", "images")
	suite.imageRepo = NewGenericObjectRepository("images", func() runtime.Object {
		return &storagev1alpha1.Image{}
	})
	suite.vulnReportRepo = NewGenericObjectRepository("vulnerability_reports", func() runtime.Object {
		return &storagev1alpha1.VulnerabilityReport{}
	})
}

func (suite *workloadScanReportRepositoryTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
	if suite.pgContainer != nil {
		err := suite.pgContainer.Terminate(context.Background())
		suite.Require().NoError(err, "failed to terminate postgres container")
	}
}

func (suite *workloadScanReportRepositoryTestSuite) SetupTest() {
	_, err := suite.db.Exec(context.Background(), "TRUNCATE TABLE workloadscanreports, images, vulnerability_reports CASCADE")
	suite.Require().NoError(err)
}

func (suite *workloadScanReportRepositoryTestSuite) TestGet() {
	ctx := context.Background()

	report := testWorkloadScanReportFactory("get-test", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "nginx",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "library/nginx",
				Tag:        "latest",
			},
		},
	})

	err := suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.repo.Create(ctx, tx, report)
	})
	suite.Require().NoError(err)

	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.imageRepo.Create(ctx, tx, &storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-image",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "library/nginx",
				Tag:        "latest",
				Platform:   "linux/amd64",
				Digest:     "sha256:abc123",
			},
		})
	})
	suite.Require().NoError(err)

	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.vulnReportRepo.Create(ctx, tx, &storagev1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-vuln",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "library/nginx",
				Tag:        "latest",
				Platform:   "linux/amd64",
				Digest:     "sha256:abc123",
			},
			Report: storagev1alpha1.Report{
				Results: []storagev1alpha1.Result{
					{
						Target: "library/nginx",
						Class:  storagev1alpha1.ClassOSPackages,
						Type:   "debian",
						Vulnerabilities: []storagev1alpha1.Vulnerability{
							{
								CVE:              "CVE-2024-0001",
								Severity:         "HIGH",
								PackageName:      "openssl",
								InstalledVersion: "1.1.1",
							},
							{
								CVE:              "CVE-2024-0002",
								Severity:         "HIGH",
								PackageName:      "libssl",
								InstalledVersion: "1.1.1",
							},
							{
								CVE:              "CVE-2024-0003",
								Severity:         "LOW",
								PackageName:      "bash",
								InstalledVersion: "5.0",
							},
						},
					},
				},
			},
		})
	})
	suite.Require().NoError(err)

	got, err := suite.repo.Get(ctx, suite.db, "get-test", "default")
	suite.Require().NoError(err)

	gotReport := got.(*storagev1alpha1.WorkloadScanReport)
	suite.Equal("get-test", gotReport.Name)
	suite.Equal("default", gotReport.Namespace)

	// Verify container statuses were populated
	suite.Require().Len(gotReport.Status.ContainerStatuses, 1)
	suite.Equal("nginx", gotReport.Status.ContainerStatuses[0].Name)
	suite.Equal(storagev1alpha1.ScanStatusScanComplete, gotReport.Status.ContainerStatuses[0].ScanStatus)

	// Verify containers were populated
	suite.Require().Len(gotReport.Containers, 1)
	suite.Equal("nginx", gotReport.Containers[0].Name)
	suite.Require().Len(gotReport.Containers[0].VulnerabilityReports, 1)
	suite.Equal("sha256:abc123", gotReport.Containers[0].VulnerabilityReports[0].ImageMetadata.Digest)

	// Verify summary was calculated from actual vulnerabilities
	suite.Equal(2, gotReport.Summary.High)
	suite.Equal(1, gotReport.Summary.Low)
}

func (suite *workloadScanReportRepositoryTestSuite) TestGet_NotFound() {
	ctx := context.Background()

	_, err := suite.repo.Get(ctx, suite.db, "nonexistent", "default")
	suite.Require().ErrorIs(err, ErrNotFound)
}

func (suite *workloadScanReportRepositoryTestSuite) TestGet_WaitingForScan() {
	ctx := context.Background()

	report := testWorkloadScanReportFactory("get-waiting", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "app",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "ghcr",
				Namespace:  "default",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
			},
		},
	})

	err := suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.repo.Create(ctx, tx, report)
	})
	suite.Require().NoError(err)

	// No images or vulnerability reports inserted

	got, err := suite.repo.Get(ctx, suite.db, "get-waiting", "default")
	suite.Require().NoError(err)

	gotReport := got.(*storagev1alpha1.WorkloadScanReport)

	// Status should be WaitingForScan since no images exist
	suite.Require().Len(gotReport.Status.ContainerStatuses, 1)
	suite.Equal(storagev1alpha1.ScanStatusWaitingForScan, gotReport.Status.ContainerStatuses[0].ScanStatus)

	// Containers should be empty
	suite.Require().Len(gotReport.Containers, 1)
	suite.Empty(gotReport.Containers[0].VulnerabilityReports)
}

func (suite *workloadScanReportRepositoryTestSuite) TestGet_ScanInProgress_ImagesExistNoScans() {
	ctx := context.Background()

	report := testWorkloadScanReportFactory("get-no-scans", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "app",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
			},
		},
	})

	err := suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.repo.Create(ctx, tx, report)
	})
	suite.Require().NoError(err)

	// Insert image but no vulnerability reports (scanning not started yet)
	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.imageRepo.Create(ctx, tx, &storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-image",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
				Platform:   "linux/amd64",
				Digest:     "sha256:abc123",
			},
		})
	})
	suite.Require().NoError(err)

	got, err := suite.repo.Get(ctx, suite.db, "get-no-scans", "default")
	suite.Require().NoError(err)

	gotReport := got.(*storagev1alpha1.WorkloadScanReport)
	suite.Require().Len(gotReport.Status.ContainerStatuses, 1)
	suite.Equal(storagev1alpha1.ScanStatusScanInProgress, gotReport.Status.ContainerStatuses[0].ScanStatus)

	// No vulnerability reports yet
	suite.Require().Len(gotReport.Containers, 1)
	suite.Empty(gotReport.Containers[0].VulnerabilityReports)
}

func (suite *workloadScanReportRepositoryTestSuite) TestGet_ScanInProgress_PartialScans() {
	ctx := context.Background()

	report := testWorkloadScanReportFactory("get-partial", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "app",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
			},
		},
	})

	err := suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.repo.Create(ctx, tx, report)
	})
	suite.Require().NoError(err)

	// Insert 2 images (multi-arch) but only 1 vulnerability report
	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.imageRepo.Create(ctx, tx, &storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-amd64",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
				Platform:   "linux/amd64",
				Digest:     "sha256:amd64",
			},
		})
	})
	suite.Require().NoError(err)

	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.imageRepo.Create(ctx, tx, &storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-arm64",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
				Platform:   "linux/arm64",
				Digest:     "sha256:arm64",
			},
		})
	})
	suite.Require().NoError(err)

	// Only one vulnerability report (scan in progress)
	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.vulnReportRepo.Create(ctx, tx, &storagev1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-vuln-amd64",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "myorg/myapp",
				Tag:        "v1.0.0",
				Platform:   "linux/amd64",
				Digest:     "sha256:amd64",
			},
			Report: storagev1alpha1.Report{},
		})
	})
	suite.Require().NoError(err)

	got, err := suite.repo.Get(ctx, suite.db, "get-partial", "default")
	suite.Require().NoError(err)

	gotReport := got.(*storagev1alpha1.WorkloadScanReport)
	suite.Require().Len(gotReport.Status.ContainerStatuses, 1)
	suite.Equal(storagev1alpha1.ScanStatusScanInProgress, gotReport.Status.ContainerStatuses[0].ScanStatus)

	// One vulnerability report exists
	suite.Require().Len(gotReport.Containers, 1)
	suite.Len(gotReport.Containers[0].VulnerabilityReports, 1)
}

func (suite *workloadScanReportRepositoryTestSuite) TestList() {
	ctx := context.Background()

	report1 := testWorkloadScanReportFactory("list-test1", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "nginx",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "library/nginx",
				Tag:        "latest",
			},
		},
	})
	report2 := testWorkloadScanReportFactory("list-test2", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "redis",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "library/redis",
				Tag:        "7",
			},
		},
	})
	report3 := testWorkloadScanReportFactory("list-test3", "other", []storagev1alpha1.ContainerRef{})

	for _, report := range []*storagev1alpha1.WorkloadScanReport{report1, report2, report3} {
		err := suite.runInTx(ctx, func(tx pgx.Tx) error {
			return suite.repo.Create(ctx, tx, report)
		})
		suite.Require().NoError(err)
	}

	err := suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.imageRepo.Create(ctx, tx, &storagev1alpha1.Image{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-image",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "library/nginx",
				Tag:        "latest",
				Platform:   "linux/amd64",
				Digest:     "sha256:nginx",
			},
		})
	})
	suite.Require().NoError(err)

	err = suite.runInTx(ctx, func(tx pgx.Tx) error {
		return suite.vulnReportRepo.Create(ctx, tx, &storagev1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-vuln",
				Namespace: "default",
			},
			ImageMetadata: storagev1alpha1.ImageMetadata{
				Registry:   "docker-registry",
				Repository: "library/nginx",
				Tag:        "latest",
				Platform:   "linux/amd64",
				Digest:     "sha256:nginx",
			},
			Report: storagev1alpha1.Report{
				Results: []storagev1alpha1.Result{
					{
						Vulnerabilities: []storagev1alpha1.Vulnerability{
							{CVE: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "openssl", InstalledVersion: "1.0"},
						},
					},
				},
			},
		})
	})
	suite.Require().NoError(err)

	// List by namespace
	items, continueToken, err := suite.repo.List(ctx, suite.db, "default", storage.ListOptions{})
	suite.Require().NoError(err)
	suite.Len(items, 2)
	suite.Empty(continueToken)

	// Verify container results were populated
	for _, item := range items {
		report := item.(*storagev1alpha1.WorkloadScanReport)
		if report.Name == "list-test1" {
			suite.Require().Len(report.Status.ContainerStatuses, 1)
			suite.Equal(storagev1alpha1.ScanStatusScanComplete, report.Status.ContainerStatuses[0].ScanStatus)
			suite.Require().Len(report.Containers, 1)
			suite.Len(report.Containers[0].VulnerabilityReports, 1)
		}
		if report.Name == "list-test2" {
			suite.Require().Len(report.Status.ContainerStatuses, 1)
			suite.Equal(storagev1alpha1.ScanStatusWaitingForScan, report.Status.ContainerStatuses[0].ScanStatus)
		}
	}

	// List all namespaces
	items, _, err = suite.repo.List(ctx, suite.db, "", storage.ListOptions{})
	suite.Require().NoError(err)
	suite.Len(items, 3)

	// List with pagination
	items, continueToken, err = suite.repo.List(ctx, suite.db, "", storage.ListOptions{
		Predicate: storage.SelectionPredicate{
			Limit: 2,
		},
	})
	suite.Require().NoError(err)
	suite.Len(items, 2)
	suite.NotEmpty(continueToken)

	items, continueToken, err = suite.repo.List(ctx, suite.db, "", storage.ListOptions{
		Predicate: storage.SelectionPredicate{
			Limit:    2,
			Continue: continueToken,
		},
	})
	suite.Require().NoError(err)
	suite.Len(items, 1)
	suite.Empty(continueToken)
}

func (suite *workloadScanReportRepositoryTestSuite) TestFindByImageRef() {
	ctx := context.Background()

	// Create WorkloadScanReports with different container configurations
	report1 := testWorkloadScanReportFactory("report-nginx", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "nginx",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "library/nginx",
				Tag:        "latest",
			},
		},
	})
	report2 := testWorkloadScanReportFactory("report-multi", "default", []storagev1alpha1.ContainerRef{
		{
			Name: "nginx",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "library/nginx",
				Tag:        "latest",
			},
		},
		{
			Name: "redis",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "default",
				Repository: "library/redis",
				Tag:        "7",
			},
		},
	})
	report3 := testWorkloadScanReportFactory("report-redis", "other", []storagev1alpha1.ContainerRef{
		{
			Name: "redis",
			ImageRef: storagev1alpha1.ImageRef{
				Registry:   "docker-registry",
				Namespace:  "other",
				Repository: "library/redis",
				Tag:        "7",
			},
		},
	})
	report4 := testWorkloadScanReportFactory("report-empty", "default", []storagev1alpha1.ContainerRef{})

	for _, report := range []*storagev1alpha1.WorkloadScanReport{report1, report2, report3, report4} {
		err := suite.runInTx(ctx, func(tx pgx.Tx) error {
			return suite.repo.Create(ctx, tx, report)
		})
		suite.Require().NoError(err)
	}

	// Find reports referencing nginx:latest in default namespace
	reports, err := suite.repo.FindByImageRef(ctx, suite.db, storagev1alpha1.ImageRef{
		Registry:   "docker-registry",
		Namespace:  "default",
		Repository: "library/nginx",
		Tag:        "latest",
	})
	suite.Require().NoError(err)
	suite.Len(reports, 2)

	names := make([]string, len(reports))
	for i, r := range reports {
		names[i] = r.Name
	}
	suite.ElementsMatch([]string{"report-nginx", "report-multi"}, names)

	// Find reports referencing redis:7 in other namespace
	reports, err = suite.repo.FindByImageRef(ctx, suite.db, storagev1alpha1.ImageRef{
		Registry:   "docker-registry",
		Namespace:  "other",
		Repository: "library/redis",
		Tag:        "7",
	})
	suite.Require().NoError(err)
	suite.Len(reports, 1)
	suite.Equal("report-redis", reports[0].Name)

	// Find reports referencing redis:7 in default namespace (only report-multi)
	reports, err = suite.repo.FindByImageRef(ctx, suite.db, storagev1alpha1.ImageRef{
		Registry:   "docker-registry",
		Namespace:  "default",
		Repository: "library/redis",
		Tag:        "7",
	})
	suite.Require().NoError(err)
	suite.Len(reports, 1)
	suite.Equal("report-multi", reports[0].Name)

	// Find reports referencing non-existent image returns empty slice
	reports, err = suite.repo.FindByImageRef(ctx, suite.db, storagev1alpha1.ImageRef{
		Registry:   "docker-registry",
		Namespace:  "default",
		Repository: "library/postgres",
		Tag:        "15",
	})
	suite.Require().NoError(err)
	suite.Empty(reports)

	// Partial match (same repo, different tag) returns empty slice
	reports, err = suite.repo.FindByImageRef(ctx, suite.db, storagev1alpha1.ImageRef{
		Registry:   "docker-registry",
		Namespace:  "default",
		Repository: "library/nginx",
		Tag:        "1.25",
	})
	suite.Require().NoError(err)
	suite.Empty(reports)
}

func TestCalculateSummary(t *testing.T) {
	repo := NewWorkloadScanReportRepository("workloadscanreports", "vulnerability_reports", "images")

	tests := []struct {
		name            string
		containers      []storagev1alpha1.ContainerResult
		expectedSummary storagev1alpha1.Summary
	}{
		{
			name:            "empty containers",
			containers:      []storagev1alpha1.ContainerResult{},
			expectedSummary: storagev1alpha1.Summary{},
		},
		{
			name: "single container with vulnerabilities",
			containers: []storagev1alpha1.ContainerResult{
				{
					Name: "app",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "openssl", InstalledVersion: "1.0"},
											{CVE: "CVE-2024-0002", Severity: "HIGH", PackageName: "libssl", InstalledVersion: "1.0"},
											{CVE: "CVE-2024-0003", Severity: "MEDIUM", PackageName: "curl", InstalledVersion: "7.0"},
											{CVE: "CVE-2024-0004", Severity: "LOW", PackageName: "bash", InstalledVersion: "5.0"},
											{CVE: "CVE-2024-0005", Severity: "UNKNOWN", PackageName: "zlib", InstalledVersion: "1.2"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSummary: storagev1alpha1.Summary{
				Critical: 1,
				High:     1,
				Medium:   1,
				Low:      1,
				Unknown:  1,
			},
		},
		{
			name: "deduplicates same CVE across platforms within container",
			containers: []storagev1alpha1.ContainerResult{
				{
					Name: "app",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							ImageMetadata: storagev1alpha1.ImageMetadata{Platform: "linux/amd64"},
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0"},
										},
									},
								},
							},
						},
						{
							ImageMetadata: storagev1alpha1.ImageMetadata{Platform: "linux/arm64"},
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											// Same CVE, same package, same version on different platform
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSummary: storagev1alpha1.Summary{
				High: 1, // Deduplicated: same CVE + package + version counts as 1
			},
		},
		{
			name: "same CVE different packages counts separately",
			containers: []storagev1alpha1.ContainerResult{
				{
					Name: "app",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0"},
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "libssl", InstalledVersion: "1.0"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSummary: storagev1alpha1.Summary{
				High: 2, // Same CVE but different packages count separately
			},
		},
		{
			name: "suppressed vulnerabilities tracked separately",
			containers: []storagev1alpha1.ContainerResult{
				{
					Name: "app",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0", Suppressed: false},
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0", Suppressed: true},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSummary: storagev1alpha1.Summary{
				High:       1,
				Suppressed: 1,
			},
		},
		{
			name: "multiple containers sum their counts",
			containers: []storagev1alpha1.ContainerResult{
				{
					Name: "nginx",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0001", Severity: "CRITICAL", PackageName: "openssl", InstalledVersion: "1.0"},
										},
									},
								},
							},
						},
					},
				},
				{
					Name: "redis",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0002", Severity: "CRITICAL", PackageName: "libc", InstalledVersion: "2.0"},
											{CVE: "CVE-2024-0003", Severity: "HIGH", PackageName: "curl", InstalledVersion: "7.0"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSummary: storagev1alpha1.Summary{
				Critical: 2,
				High:     1,
			},
		},
		{
			name: "same CVE in different containers counts multiple times",
			containers: []storagev1alpha1.ContainerResult{
				{
					Name: "nginx",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0"},
										},
									},
								},
							},
						},
					},
				},
				{
					Name: "redis",
					VulnerabilityReports: []storagev1alpha1.WorkloadScanVulnerabilityReport{
						{
							Report: storagev1alpha1.Report{
								Results: []storagev1alpha1.Result{
									{
										Vulnerabilities: []storagev1alpha1.Vulnerability{
											// Same CVE in different container
											{CVE: "CVE-2024-0001", Severity: "HIGH", PackageName: "openssl", InstalledVersion: "1.0"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedSummary: storagev1alpha1.Summary{
				High: 2, // Same CVE in different containers counts separately
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := &storagev1alpha1.WorkloadScanReport{
				Containers: test.containers,
			}

			repo.calculateSummary(report)

			assert.Equal(t, test.expectedSummary.Critical, report.Summary.Critical, "Critical count mismatch")
			assert.Equal(t, test.expectedSummary.High, report.Summary.High, "High count mismatch")
			assert.Equal(t, test.expectedSummary.Medium, report.Summary.Medium, "Medium count mismatch")
			assert.Equal(t, test.expectedSummary.Low, report.Summary.Low, "Low count mismatch")
			assert.Equal(t, test.expectedSummary.Unknown, report.Summary.Unknown, "Unknown count mismatch")
			assert.Equal(t, test.expectedSummary.Suppressed, report.Summary.Suppressed, "Suppressed count mismatch")
		})
	}
}

func (suite *workloadScanReportRepositoryTestSuite) runInTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := suite.db.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func testWorkloadScanReportFactory(name, namespace string, containers []storagev1alpha1.ContainerRef) *storagev1alpha1.WorkloadScanReport {
	return &storagev1alpha1.WorkloadScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: storagev1alpha1.WorkloadScanReportSpec{
			Containers: containers,
		},
	}
}
