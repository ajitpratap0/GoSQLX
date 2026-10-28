-- Rotate system-versioned history partitions.
ALTER TABLE audit_log DROP PARTITION IF EXISTS p_hist0;
ALTER TABLE audit_log ADD PARTITION IF NOT EXISTS (PARTITION p_hist9 HISTORY);
