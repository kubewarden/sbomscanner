package datafeed

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/stephenafamo/bob/dialect/sqlite"
	"github.com/stephenafamo/bob/dialect/sqlite/im"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	_ "modernc.org/sqlite" // sqlite driver
)

// sqliteDriver is the database/sql driver name registered by modernc.org/sqlite.
const sqliteDriver = "sqlite"

// entriesTable holds one JSON entry per CVE. Every feed database has this one table.
const entriesTable = "entries"

// schema is the layout shared by every feed database.
const schema = `CREATE TABLE entries (cve_id TEXT PRIMARY KEY, entry TEXT NOT NULL);`

// ErrNotFound reports that a CVE has no entry in a database.
var ErrNotFound = errors.New("not found")

// Entry is one row of a feed database: the CVE and its data as JSON.
type Entry struct {
	CVE  string
	JSON []byte
}

// Database reads a feed database written by this package.
type Database struct {
	db     *sql.DB
	lookup *sql.Stmt
}

// OpenDatabase opens the feed database at path read-only.
// immutable tells SQLite the file cannot change while open, so it takes no locks.
func OpenDatabase(ctx context.Context, path string) (*Database, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	db, err := sql.Open(sqliteDriver, "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	query, _, err := sqlite.Select(
		sm.Columns("entry"),
		sm.From(entriesTable),
		sm.Where(sqlite.Quote("cve_id").EQ(sqlite.Arg(""))),
	).Build(ctx)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("build lookup query: %w", err), db.Close())
	}
	lookup, err := db.PrepareContext(ctx, query)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("prepare lookup in %s: %w", path, err), db.Close())
	}
	return &Database{db: db, lookup: lookup}, nil
}

// Lookup returns the JSON entry of cve, or ErrNotFound when the CVE has none.
func (d *Database) Lookup(ctx context.Context, cve string) ([]byte, error) {
	var entry []byte
	err := d.lookup.QueryRowContext(ctx, cve).Scan(&entry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", cve, err)
	}
	return entry, nil
}

// Close releases the database.
func (d *Database) Close() error {
	if err := errors.Join(d.lookup.Close(), d.db.Close()); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	return nil
}

// writeDatabase creates a fresh feed database at path with the given entries.
// The bytes depend only on the entries: the file is new, rows are inserted sorted
// by CVE, and VACUUM compacts the pages. An unchanged feed keeps its layer digest.
func writeDatabase(ctx context.Context, path string, entries []Entry) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	db, err := sql.Open(sqliteDriver, path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer db.Close()

	// A single writer on a throwaway file: no journal, no fsync.
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;`); err != nil {
		return fmt.Errorf("configure %s: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema in %s: %w", path, err)
	}

	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b Entry) int { return strings.Compare(a.CVE, b.CVE) })

	query, _, err := sqlite.Insert(
		im.Into(entriesTable, "cve_id", "entry"),
		im.Values(sqlite.Arg("", "")),
	).Build(ctx)
	if err != nil {
		return fmt.Errorf("build insert query: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s: %w", path, err)
	}
	insert, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return errors.Join(fmt.Errorf("prepare insert: %w", err), tx.Rollback())
	}
	defer insert.Close()
	for _, entry := range sorted {
		if _, err := insert.ExecContext(ctx, entry.CVE, string(entry.JSON)); err != nil {
			return errors.Join(fmt.Errorf("insert %s: %w", entry.CVE, err), tx.Rollback())
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("vacuum %s: %w", path, err)
	}
	// The write ran without journal or fsync, so check the result before it ships.
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("check %s: %w", path, err)
	}
	if integrity != "ok" {
		return fmt.Errorf("check %s: %s", path, integrity)
	}
	return nil
}
