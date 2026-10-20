package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/distrust"
)

// A small SQL driver keeps refresh failure tests independent of PostgreSQL.
// Actual schema and SQL behavior are also checked manually with PostgreSQL 18.
type distrustSQL struct {
	locked, committed, rolledBack bool
	queries                       []string
	failRuleWrite                 bool
}

func (s *distrustSQL) Connect(context.Context) (driver.Conn, error) { return s, nil }
func (s *distrustSQL) Driver() driver.Driver                        { return s }
func (s *distrustSQL) Open(string) (driver.Conn, error)             { return s, nil }
func (s *distrustSQL) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (s *distrustSQL) Close() error              { return nil }
func (s *distrustSQL) Begin() (driver.Tx, error) { return s, nil }
func (s *distrustSQL) Commit() error             { s.committed = true; return nil }
func (s *distrustSQL) Rollback() error           { s.rolledBack = true; return nil }
func (s *distrustSQL) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	s.queries = append(s.queries, q)
	if s.failRuleWrite && strings.Contains(q, "INSERT INTO certificate_distrust_rules") {
		return nil, errors.New("write failed")
	}
	return driver.RowsAffected(1), nil
}
func (s *distrustSQL) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(q, "pg_try_advisory_xact_lock") {
		return nil, errors.New("unexpected query")
	}
	return &lockRows{locked: s.locked}, nil
}

type lockRows struct{ done, locked bool }

func (r *lockRows) Columns() []string { return []string{"locked"} }
func (r *lockRows) Close() error      { return nil }
func (r *lockRows) Next(v []driver.Value) error {
	if r.done {
		return io.EOF
	}
	v[0] = r.locked
	r.done = true
	return nil
}

func TestRefreshDistrustTransactions(t *testing.T) {
	valid := distrust.Rule{Source: distrust.OneCRL, SourceRecordID: "rule", Platform: "mozilla", Status: "blocked", MatchType: "certificate_sha256", CertificateSHA256: make([]byte, 32)}
	tests := []struct {
		name                                        string
		rules                                       []distrust.Rule
		fetchErr                                    error
		locked, writeFailure, wantCommit, wantError bool
	}{
		{name: "successful snapshot", rules: []distrust.Rule{valid}, locked: true, wantCommit: true},
		{name: "successful withdrawal", locked: true, wantCommit: true},
		{name: "network failure", fetchErr: errors.New("offline"), locked: true, wantCommit: true, wantError: true},
		{name: "invalid rules", rules: []distrust.Rule{{Source: distrust.OneCRL}}, locked: true, wantCommit: true, wantError: true},
		{name: "duplicate rules", rules: []distrust.Rule{valid, valid}, locked: true, wantCommit: true, wantError: true},
		{name: "database failure", rules: []distrust.Rule{valid}, locked: true, writeFailure: true, wantError: true},
		{name: "concurrent refresh", wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &distrustSQL{locked: tc.locked, failRuleWrite: tc.writeFailure}
			database := sql.OpenDB(mock)
			defer database.Close()
			repo := NewRepository(&DB{DB: database})
			fetched := false
			err := repo.RefreshDistrust(context.Background(), distrust.OneCRL, func() ([]distrust.Rule, error) { fetched = true; return tc.rules, tc.fetchErr })
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v", err)
			}
			if mock.committed != tc.wantCommit {
				t.Fatalf("committed=%v", mock.committed)
			}
			if !tc.wantCommit && !mock.rolledBack {
				t.Fatal("failed transaction did not roll back")
			}
			if !tc.locked && fetched {
				t.Fatal("concurrent refresh fetched without lock")
			}
			if tc.wantCommit && tc.wantError {
				for _, q := range mock.queries {
					if strings.Contains(q, "certificate_distrust_rules") {
						t.Fatal("failed snapshot modified rules")
					}
				}
				if !strings.Contains(strings.Join(mock.queries, "\n"), "last_error=$2") {
					t.Fatal("failure not recorded")
				}
			}
		})
	}
}
