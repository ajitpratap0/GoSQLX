-- Basic SELECT queries for testing
-- This file consolidates simple test queries

-- Basic SELECT with WHERE
SELECT name, email FROM users WHERE active = true;

-- SELECT with wildcard (for testing SELECT * detection)
SELECT * FROM users;

-- Simple JOIN
SELECT u.name, p.title FROM users u LEFT JOIN posts p ON u.id = p.user_id WHERE u.active = true ORDER BY u.name;

-- INSERT statement
INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com');

-- UPDATE statement  
UPDATE users SET email = 'newemail@example.com' WHERE id = 1;