-- 000010 deduplicates pre-switch Microsoft links where both an oid-keyed row
-- and a sub-keyed row exist for the same user.
-- When a user logged in after the sub switch, an attested address inserted
-- a second link row keyed on sub. Deduplicate by removing the older link
-- when multiple Microsoft links exist for the same user.
DELETE FROM oauth_accounts a
WHERE a.provider_id = 'microsoft'
  AND EXISTS (
    SELECT 1 FROM oauth_accounts b
    WHERE b.user_id = a.user_id
      AND b.provider_id = 'microsoft'
      AND (b.created_at > a.created_at OR (b.created_at = a.created_at AND b.id > a.id))
  );
