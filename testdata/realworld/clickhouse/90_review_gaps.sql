-- Sample finalized events for a traffic report.
SELECT h.site_id, COUNT(*) FROM hits AS h FINAL SAMPLE 1/10 OFFSET 1/2 WHERE h.status = 200 GROUP BY h.site_id;

-- Join sampled sessions to sampled finalized hits.
SELECT s.site_id, COUNT(*) FROM sessions AS s SAMPLE 0.1 JOIN hits AS h FINAL SAMPLE 0.1 ON h.session_id = s.id GROUP BY s.site_id;
