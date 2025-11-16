SELECT
    id
    , name
    , email
FROM users
WHERE
    active = true AND role IN ('admin', 'user')
ORDER BY created_at DESC
