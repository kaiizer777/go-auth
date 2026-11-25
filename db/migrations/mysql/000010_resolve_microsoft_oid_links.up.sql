-- 000010 deduplicates pre-switch Microsoft links keyed on (provider_id, provider_user_id).
-- Survivor rule: verified beats unverified, then newest created_at, then highest id.
DELETE a FROM oauth_accounts a
INNER JOIN oauth_accounts b ON a.provider_id = b.provider_id AND a.provider_user_id = b.provider_user_id
WHERE a.provider_id = 'microsoft'
  AND (
    (b.verified > a.verified)
    OR (b.verified = a.verified AND b.created_at > a.created_at)
    OR (b.verified = a.verified AND b.created_at = a.created_at AND b.id > a.id)
  );
