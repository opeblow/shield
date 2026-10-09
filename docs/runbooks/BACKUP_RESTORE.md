# Runbook — backup and restore drill

A backup is only real once a restore has been proven. Run this drill on a
schedule and after any schema change.

## Backup
1. Enable managed PostgreSQL automated snapshots with point-in-time recovery.
2. Encrypt snapshots at rest with a KMS key separate from the application keyring.
3. Export the S3-compatible object-storage versioning policy.
4. Record the retention window (suggested: 30 days PITR, 12 months monthly).

## Restore drill (quarterly, non-production)
1. Restore the latest snapshot into a throwaway instance.
2. Apply `infra/migrations/*.sql` and confirm `psql -c '\dt'` shows every table.
3. Run `npm run seed` against the restored instance; confirm template/brand counts.
4. Start a dev API pointed at the restored DB and verify: `/readyz` ready, an
   authenticated `POST /v1/scans` persists, and a `GET /v1/usage` returns rows.
5. Measure and record RTO (time to serve) and RPO (data age at restore).

## Acceptance
- RTO within the agreed target; RPO = 0 for committed transactions.
- RLS still isolates tenants on the restored data (spot-check two tenants).
- Evidence (timestamps, row counts, operator) attached to the drill record.
