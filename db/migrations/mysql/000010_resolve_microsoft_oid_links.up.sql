-- 000010 deduplicates pre-switch Microsoft links where both an oid-keyed row
-- and a sub-keyed row exist for the same user.
DELETE a FROM oauth_accounts a
INNER JOIN oauth_accounts b ON a.user_id = b.user_id AND a.provider_id = b.provider_id
WHERE a.provider_id = 'microsoft'
  AND (b.created_at > a.created_at OR (b.created_at = a.created_at AND b.id > a.id));
