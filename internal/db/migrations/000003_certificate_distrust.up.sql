CREATE TABLE certificate_distrust_sources (
 source text PRIMARY KEY CHECK (source IN ('mozilla_onecrl','ccadb')),
 last_attempted_at timestamptz NOT NULL,
 last_successful_at timestamptz,
 active_rules integer NOT NULL DEFAULT 0 CHECK (active_rules >= 0),
 last_error text NOT NULL DEFAULT ''
);

CREATE TABLE certificate_distrust_rules (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 source text NOT NULL REFERENCES certificate_distrust_sources(source),
 source_record_id text NOT NULL CHECK (source_record_id <> ''),
 platform text NOT NULL CHECK (platform IN ('mozilla','apple','chrome','microsoft')),
 status text NOT NULL CHECK (status IN ('blocked','disabled','removed')),
 match_type text NOT NULL CHECK (match_type IN ('certificate_sha256','issuer_serial','subject_public_key_hash')),
 certificate_sha256 bytea,
 issuer_name_der bytea,
 serial_number bytea,
 subject_name_der bytea,
 public_key_hash bytea,
 reason text NOT NULL DEFAULT '',
 reference_url text NOT NULL DEFAULT '',
 effective_at timestamptz,
 first_seen_at timestamptz NOT NULL,
 last_seen_at timestamptz NOT NULL,
 withdrawn_at timestamptz,
 UNIQUE (source,source_record_id,platform),
 CHECK (last_seen_at >= first_seen_at),
 CHECK (
  (match_type='certificate_sha256' AND certificate_sha256 IS NOT NULL AND octet_length(certificate_sha256)=32 AND issuer_name_der IS NULL AND serial_number IS NULL AND subject_name_der IS NULL AND public_key_hash IS NULL)
  OR (match_type='issuer_serial' AND issuer_name_der IS NOT NULL AND octet_length(issuer_name_der)>0 AND serial_number IS NOT NULL AND octet_length(serial_number)>0 AND certificate_sha256 IS NULL AND subject_name_der IS NULL AND public_key_hash IS NULL)
  OR (match_type='subject_public_key_hash' AND subject_name_der IS NOT NULL AND octet_length(subject_name_der)>0 AND public_key_hash IS NOT NULL AND octet_length(public_key_hash)=32 AND certificate_sha256 IS NULL AND issuer_name_der IS NULL AND serial_number IS NULL)
 )
);
CREATE INDEX idx_certificate_distrust_active ON certificate_distrust_rules(source) WHERE withdrawn_at IS NULL;
COMMENT ON TABLE certificate_distrust_rules IS 'Source-specific platform distrust evidence, independent of the observed certificate catalog. Absence is not proof of trust.';
