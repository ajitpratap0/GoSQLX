-- Simple SELECT with backtick identifiers (MySQL style)
-- Complexity: Simple
-- Tests: Backtick identifiers, basic WHERE
SELECT `id`, `name`, `email` FROM `users` WHERE `active` = 1;
