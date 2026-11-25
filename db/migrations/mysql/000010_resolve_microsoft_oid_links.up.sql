-- 000010 deduplicates pre-switch Microsoft links where both an oid-keyed row
-- and a sub-keyed row exist for the same user with the same email.
-- Survivor rule: verified beats unverified, then newest created_at, then highest id.
DELETE a FROM oauth_accounts a
INNER JOIN oauth_accounts b ON a.user_id = b.user_id AND a.provider_id = b.provider_id AND a.email = b.email AND a.email != ''
WHERE a.provider_id = 'microsoft'
  AND (
    (b.verified > a.verified)
    OR (b.verified = a.verified AND b.created_at > a.created_at)
    OR (b.verified = a.verified AND b.created_at = a.created_at AND b.id > a.id)
  );
