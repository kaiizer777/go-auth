-- 000010 deduplicates pre-switch Microsoft links where both an oid-keyed row
-- and a sub-keyed row exist for the same user with the same email.
-- Survivor rule: verified beats unverified, then newest created_at, then highest id.
DELETE FROM oauth_accounts a
WHERE a.provider_id = 'microsoft'
  AND EXISTS (
    SELECT 1 FROM oauth_accounts b
    WHERE b.user_id = a.user_id
      AND b.provider_id = a.provider_id
      AND a.email = b.email AND a.email != ''
      AND (
        (b.verified > a.verified)
        OR (b.verified = a.verified AND b.created_at > a.created_at)
        OR (b.verified = a.verified AND b.created_at = a.created_at AND b.id > a.id)
      )
  );
