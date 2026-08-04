package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kubewarden/sbomscanner/internal/sbomscannerdb/oci"
)

// inspectRenderer writes a manifest view to w in a specific format.
type inspectRenderer func(w io.Writer, view oci.ManifestView) error

// inspectFormats maps a --format value to its renderer. Add an entry here to
// support a new inspect output (e.g. "table") without touching the command.
var inspectFormats = map[string]inspectRenderer{
	"json": renderInspectJSON,
}

// defaultInspectFormat is used when --format is not provided.
const defaultInspectFormat = "json"

// supportedInspectFormats returns the known format names, sorted, for messages.
func supportedInspectFormats() string {
	names := make([]string, 0, len(inspectFormats))
	for name := range inspectFormats {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// renderInspectJSON writes the view as indented JSON.
func renderInspectJSON(w io.Writer, view oci.ManifestView) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(view); err != nil {
		return fmt.Errorf("encode manifest as json: %w", err)
	}
	return nil
}
