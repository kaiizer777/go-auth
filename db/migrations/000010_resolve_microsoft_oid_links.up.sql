-- 000010 deduplicates pre-switch Microsoft links keyed on (provider_id, provider_user_id).
-- Survivor rule: verified beats unverified, then newest created_at, then highest id.
DELETE FROM oauth_accounts a
WHERE a.provider_id = 'microsoft'
  AND EXISTS (
    SELECT 1 FROM oauth_accounts b
    WHERE b.provider_id = a.provider_id
      AND b.provider_user_id = a.provider_user_id
      AND (
        (b.verified > a.verified)
        OR (b.verified = a.verified AND b.created_at > a.created_at)
        OR (b.verified = a.verified AND b.created_at = a.created_at AND b.id > a.id)
      )
  );
