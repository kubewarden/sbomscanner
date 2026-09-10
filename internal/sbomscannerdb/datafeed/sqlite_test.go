package datafeed

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabase_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.sqlite")
	entries := []Entry{
		{CVE: "CVE-2021-44228", JSON: []byte(`{"a":1}`)},
		{CVE: "CVE-2019-0708", JSON: []byte(`{"a":2}`)},
	}
	require.NoError(t, writeDatabase(context.Background(), path, entries))

	db, err := OpenDatabase(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	entry, err := db.Lookup(context.Background(), "CVE-2019-0708")
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":2}`, string(entry))

	_, err = db.Lookup(context.Background(), "CVE-0000-0000")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestWriteDatabase_IsReproducible(t *testing.T) {
	// The same entries in a different order must give the same bytes.
	entries := []Entry{
		{CVE: "CVE-2021-44228", JSON: []byte(`{"a":1}`)},
		{CVE: "CVE-2019-0708", JSON: []byte(`{"a":2}`)},
	}
	first := writeAndRead(t, entries)
	second := writeAndRead(t, []Entry{entries[1], entries[0]})
	assert.Equal(t, first, second)
	assert.NotEmpty(t, first)
}

// writeAndRead writes entries into a fresh database and returns the file bytes.
func writeAndRead(t *testing.T, entries []Entry) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.sqlite")
	require.NoError(t, writeDatabase(context.Background(), path, entries))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// lookupJSON returns the entry of cve in the database at path, decoded into out.
func lookupJSON(t *testing.T, path, cve string, out any) {
	t.Helper()
	db, err := OpenDatabase(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	entry, err := db.Lookup(context.Background(), cve)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(entry, out))
}
