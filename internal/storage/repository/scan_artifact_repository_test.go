package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"k8s.io/apimachinery/pkg/runtime"

	storagev1alpha1 "github.com/kubewarden/sbomscanner/api/storage/v1alpha1"
)

func (suite *repositoryTestSuite) TestScanArtifactRepository_Deduplication() {
	ctx := context.Background()

	// Create two scans with the same digest
	sbom1 := testSBOMFactory("scan1", "default", "sha256:shared-digest")
	sbom1.Labels = map[string]string{"scan": "first"}

	sbom2 := testSBOMFactory("scan2", "default", "sha256:shared-digest")
	sbom2.Labels = map[string]string{"scan": "second"}

	err := suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Create(ctx, tx, sbom1)
	})
	suite.Require().NoError(err)

	err = suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Create(ctx, tx, sbom2)
	})
	suite.Require().NoError(err)

	// Verify only one artifact row exists
	var artifactCount int64
	err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM sbom_artifacts").Scan(&artifactCount)
	suite.Require().NoError(err)
	suite.Equal(int64(1), artifactCount)

	// Verify two scan rows exist
	var scanCount int64
	err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM sboms").Scan(&scanCount)
	suite.Require().NoError(err)
	suite.Equal(int64(2), scanCount)

	sbom1.SPDX = runtime.RawExtension{Raw: []byte(`{"updated":"content"}`)}
	err = suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Update(ctx, tx, sbom1.Name, sbom1.Namespace, sbom1)
	})
	suite.Require().NoError(err)

	// Verify artifact content is updated for both sboms
	got1, err := suite.scanArtifactRepo.Get(ctx, suite.db, "scan1", "default")
	suite.Require().NoError(err)
	gotSBOM1 := got1.(*storagev1alpha1.SBOM)
	suite.JSONEq(`{"updated":"content"}`, string(gotSBOM1.SPDX.Raw))

	got2, err := suite.scanArtifactRepo.Get(ctx, suite.db, "scan2", "default")
	suite.Require().NoError(err)
	gotSBOM2 := got2.(*storagev1alpha1.SBOM)
	suite.JSONEq(`{"updated":"content"}`, string(gotSBOM2.SPDX.Raw))

	sbom1.Labels["scan"] = "first-updated"
	err = suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Update(ctx, tx, sbom1.Name, sbom1.Namespace, sbom1)
	})
	suite.Require().NoError(err)

	// Verify labels are updated independently
	got1, err = suite.scanArtifactRepo.Get(ctx, suite.db, "scan1", "default")
	suite.Require().NoError(err)
	gotSBOM1 = got1.(*storagev1alpha1.SBOM)
	suite.Equal(map[string]string{"scan": "first-updated"}, gotSBOM1.Labels)

	got2, err = suite.scanArtifactRepo.Get(ctx, suite.db, "scan2", "default")
	suite.Require().NoError(err)
	gotSBOM2 = got2.(*storagev1alpha1.SBOM)
	suite.Equal(map[string]string{"scan": "second"}, gotSBOM2.Labels)
}

func (suite *repositoryTestSuite) TestScanArtifactRepository_ObjectReconstruction() {
	ctx := context.Background()

	// Create two scans with the same digest but different labels and annotations
	sbom1 := testSBOMFactory("recon1", "default", "sha256:recon-digest")
	sbom1.Labels = map[string]string{"scan": "first"}
	sbom1.Annotations = map[string]string{"note": "first scan"}

	sbom2 := testSBOMFactory("recon2", "default", "sha256:recon-digest")
	sbom2.Labels = map[string]string{"scan": "second"}
	sbom2.Annotations = map[string]string{"note": "second scan"}

	err := suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Create(ctx, tx, sbom1)
	})
	suite.Require().NoError(err)

	err = suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Create(ctx, tx, sbom2)
	})
	suite.Require().NoError(err)

	// Verify each scan has its own labels and annotations
	got1, err := suite.scanArtifactRepo.Get(ctx, suite.db, "recon1", "default")
	suite.Require().NoError(err)
	gotSBOM1 := got1.(*storagev1alpha1.SBOM)
	suite.Equal(map[string]string{"scan": "first"}, gotSBOM1.Labels)
	suite.Equal(map[string]string{"note": "first scan"}, gotSBOM1.Annotations)

	got2, err := suite.scanArtifactRepo.Get(ctx, suite.db, "recon2", "default")
	suite.Require().NoError(err)
	gotSBOM2 := got2.(*storagev1alpha1.SBOM)
	suite.Equal(map[string]string{"scan": "second"}, gotSBOM2.Labels)
	suite.Equal(map[string]string{"note": "second scan"}, gotSBOM2.Annotations)
}

func (suite *repositoryTestSuite) TestScanArtifactRepository_GarbageCollection() {
	ctx := context.Background()

	// Create two scans with the same digest
	sbom1 := testSBOMFactory("gc1", "default", "sha256:gc-digest")
	sbom2 := testSBOMFactory("gc2", "default", "sha256:gc-digest")

	err := suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Create(ctx, tx, sbom1)
	})
	suite.Require().NoError(err)

	err = suite.withTx(ctx, func(tx pgx.Tx) error {
		return suite.scanArtifactRepo.Create(ctx, tx, sbom2)
	})
	suite.Require().NoError(err)

	// Delete first scan, artifact should remain
	_, err = suite.withTxReturn(ctx, func(tx pgx.Tx) (runtime.Object, error) {
		return suite.scanArtifactRepo.Delete(ctx, tx, "gc1", "default")
	})
	suite.Require().NoError(err)

	var artifactCount int64
	err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM sbom_artifacts").Scan(&artifactCount)
	suite.Require().NoError(err)
	suite.Equal(int64(1), artifactCount, "artifact should remain after first delete")

	// Delete second scan, artifact should be garbage collected
	_, err = suite.withTxReturn(ctx, func(tx pgx.Tx) (runtime.Object, error) {
		return suite.scanArtifactRepo.Delete(ctx, tx, "gc2", "default")
	})
	suite.Require().NoError(err)

	err = suite.db.QueryRow(ctx, "SELECT COUNT(*) FROM sbom_artifacts").Scan(&artifactCount)
	suite.Require().NoError(err)
	suite.Equal(int64(0), artifactCount, "artifact should be removed after last scan deleted")
}
