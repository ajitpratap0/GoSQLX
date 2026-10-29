-- Roll historical order partitions forward while retaining a catch-all range.
ALTER TABLE order_history PARTITION BY RANGE (YEAR(ordered_at)) (PARTITION p2025 VALUES LESS THAN (2026), PARTITION p_future VALUES LESS THAN MAXVALUE);
ALTER TABLE order_history REORGANIZE PARTITION p_future INTO (PARTITION p2026 VALUES LESS THAN (2027), PARTITION p_future VALUES LESS THAN MAXVALUE);

-- Purge and compact archived order partitions online.
ALTER TABLE order_history TRUNCATE PARTITION ALL;
ALTER TABLE order_history DROP PARTITION p2019, p2020, ALGORITHM=INPLACE, LOCK=NONE;
ALTER TABLE order_history EXCHANGE PARTITION p2025 WITH TABLE order_archive WITHOUT VALIDATION;
