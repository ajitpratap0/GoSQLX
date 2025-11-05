-- LEFT JOIN with NULL handling
-- Complexity: Medium
-- Tests: LEFT JOIN, IS NULL, COALESCE function
SELECT u.name, COALESCE(p.title, 'No posts') as post_title
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
WHERE p.id IS NULL OR p.published = true;
