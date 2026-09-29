UPDATE tasks
SET error_message = NULL,
    updated_at = now()
WHERE status = 'SUCCEEDED'
  AND error_message IS NOT NULL;
