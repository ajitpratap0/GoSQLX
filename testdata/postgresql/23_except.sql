-- EXCEPT set operation
-- Complexity: Medium
-- Tests: EXCEPT operator (PostgreSQL syntax)
SELECT email FROM users
EXCEPT
SELECT email FROM unsubscribed;
