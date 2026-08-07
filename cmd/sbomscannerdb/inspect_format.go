package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// renderInspectJSON writes the view as indented JSON.
func renderInspectJSON(w io.Writer, view oci.ManifestView) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(view); err != nil {
		return fmt.Errorf("encode manifest as json: %w", err)
	}
	return nil
}
