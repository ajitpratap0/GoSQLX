-- OUTPUT clause in INSERT/UPDATE/DELETE
-- Complexity: Medium
-- Tests: OUTPUT clause for returning affected rows
INSERT INTO users (name, email)
OUTPUT INSERTED.id, INSERTED.name
VALUES ('John Doe', 'john@example.com');
