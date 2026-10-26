-- Scenario: JSON-heavy document storage app
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, payload TEXT NOT NULL CHECK (json_valid(payload)));
INSERT INTO events (payload) VALUES ('{"type":"click","user":{"id":7,"name":"Zed"},"tags":["a","b"]}');
INSERT INTO events (payload) VALUES (json_object('type', 'view', 'n', 3));
SELECT json_extract(payload, '$.type') FROM events;
SELECT json_extract(payload, '$.user.id', '$.user.name') FROM events;
SELECT payload -> 'type' FROM events;
SELECT payload ->> 'type' FROM events;
SELECT payload -> '$.user' ->> '$.name' FROM events;
SELECT payload ->> '$.tags[0]' AS first_tag FROM events;
SELECT id FROM events WHERE payload ->> 'type' = 'click';
SELECT id FROM events WHERE json_extract(payload, '$.user.id') = 7 AND payload ->> '$.n' > 2;
SELECT json_array(1, 2, 'x'), json_array_length('[1,2,3]'), json_type(payload, '$.user') FROM events;
SELECT json_set(payload, '$.seen', 1), json_insert(payload, '$.a', 2), json_replace(payload, '$.type', 'x'), json_remove(payload, '$.tags') FROM events;
SELECT json_patch(payload, '{"a":null}') FROM events;
SELECT json_group_array(payload ->> 'type') FROM events;
SELECT json_group_object(id, payload ->> 'type') FROM events;
SELECT e.id, j.value FROM events e, json_each(e.payload, '$.tags') AS j;
SELECT e.id, j.key, j.value, j.type FROM events AS e JOIN json_each(e.payload) AS j ON 1 = 1;
SELECT j.fullkey, j.atom FROM events e, json_tree(e.payload) j WHERE j.atom IS NOT NULL;
SELECT jsonb(payload), jsonb_extract(payload, '$.type'), json(jsonb(payload)) FROM events;
SELECT jsonb_set(jsonb(payload), '$.k', 'v') FROM events;
CREATE INDEX idx_events_type ON events (json_extract(payload, '$.type'));
CREATE INDEX idx_events_type2 ON events ((payload ->> '$.type'));
UPDATE events SET payload = json_set(payload, '$.processed', json('true')) WHERE payload ->> 'type' = 'click';
UPDATE events SET payload = json_remove(payload, '$.user.name') WHERE id = 1 RETURNING id, payload;
SELECT json_quote('x'), json_valid(payload) FROM events;
WITH t AS (SELECT payload ->> 'type' AS type, count(*) AS n FROM events GROUP BY 1)
SELECT type, n, round(100.0 * n / sum(n) OVER (), 1) AS pct FROM t ORDER BY n DESC;
