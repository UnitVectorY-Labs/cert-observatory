package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/distrust"
)

// RefreshDistrust serializes each source's complete refresh, including its fetch.
// On fetch/validation failure only source freshness changes; rules remain intact.
func (r *Repository) RefreshDistrust(ctx context.Context, source string, fetch func() ([]distrust.Rule, error)) error {
	if source != distrust.OneCRL && source != distrust.CCADB {
		return fmt.Errorf("unknown distrust source %q", source)
	}
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(43120, hashtext($1))`, source).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("distrust refresh already running for %s", source)
	}
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, `INSERT INTO certificate_distrust_sources(source,last_attempted_at) VALUES($1,$2)
 ON CONFLICT(source) DO UPDATE SET last_attempted_at=EXCLUDED.last_attempted_at`, source, now)
	if err != nil {
		return err
	}
	rules, fetchErr := fetch()
	if fetchErr == nil {
		seen := map[string]bool{}
		for _, v := range rules {
			if e := v.Validate(); e != nil {
				fetchErr = e
				break
			}
			key := v.SourceRecordID + "\x00" + v.Platform
			if v.Source != source || seen[key] {
				fetchErr = fmt.Errorf("wrong source or duplicate rule")
				break
			}
			seen[key] = true
		}
	}
	if fetchErr != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE certificate_distrust_sources SET last_error=$2 WHERE source=$1`, source, fetchErr.Error()); err != nil {
			return fmt.Errorf("fetch: %v; record failure: %w", fetchErr, err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		return fetchErr
	}
	for _, v := range rules {
		_, err = tx.ExecContext(ctx, `INSERT INTO certificate_distrust_rules
   (source,source_record_id,platform,status,match_type,certificate_sha256,issuer_name_der,serial_number,subject_name_der,public_key_hash,reason,reference_url,effective_at,first_seen_at,last_seen_at)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
   ON CONFLICT(source,source_record_id,platform) DO UPDATE SET
   status=EXCLUDED.status,match_type=EXCLUDED.match_type,certificate_sha256=EXCLUDED.certificate_sha256,
   issuer_name_der=EXCLUDED.issuer_name_der,serial_number=EXCLUDED.serial_number,subject_name_der=EXCLUDED.subject_name_der,
   public_key_hash=EXCLUDED.public_key_hash,reason=EXCLUDED.reason,reference_url=EXCLUDED.reference_url,effective_at=EXCLUDED.effective_at,
   last_seen_at=EXCLUDED.last_seen_at,withdrawn_at=NULL`, v.Source, v.SourceRecordID, v.Platform, v.Status, v.MatchType, v.CertificateSHA256, v.IssuerNameDER, v.SerialNumber, v.SubjectNameDER, v.PublicKeyHash, v.Reason, v.ReferenceURL, v.EffectiveAt, now)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE certificate_distrust_rules SET withdrawn_at=$2 WHERE source=$1 AND withdrawn_at IS NULL AND last_seen_at < $2`, source, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE certificate_distrust_sources SET last_successful_at=$2,active_rules=$3,last_error='' WHERE source=$1`, source, now, len(rules))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DistrustSnapshot reads rules and freshness from one consistent database snapshot.
func (r *Repository) DistrustSnapshot(ctx context.Context) (*distrust.Snapshot, error) {
	tx, err := r.db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	snapshot := &distrust.Snapshot{}
	rows, err := tx.QueryContext(ctx, `SELECT source,last_attempted_at,last_successful_at,active_rules,last_error FROM certificate_distrust_sources ORDER BY source`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s distrust.SourceState
		if err = rows.Scan(&s.Source, &s.LastAttemptedAt, &s.LastSuccessfulAt, &s.ActiveRules, &s.LastError); err != nil {
			rows.Close()
			return nil, err
		}
		snapshot.Sources = append(snapshot.Sources, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT source,source_record_id,platform,status,match_type,certificate_sha256,issuer_name_der,serial_number,subject_name_der,public_key_hash,reason,reference_url,effective_at,first_seen_at,last_seen_at FROM certificate_distrust_rules WHERE withdrawn_at IS NULL ORDER BY source,platform,source_record_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v distrust.Rule
		if err = rows.Scan(&v.Source, &v.SourceRecordID, &v.Platform, &v.Status, &v.MatchType, &v.CertificateSHA256, &v.IssuerNameDER, &v.SerialNumber, &v.SubjectNameDER, &v.PublicKeyHash, &v.Reason, &v.ReferenceURL, &v.EffectiveAt, &v.FirstSeenAt, &v.LastSeenAt); err != nil {
			rows.Close()
			return nil, err
		}
		snapshot.Rules = append(snapshot.Rules, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (r *WebRepository) DistrustSnapshot(ctx context.Context) (*distrust.Snapshot, error) {
	return r.repo.DistrustSnapshot(ctx)
}
