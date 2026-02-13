-- Ent-style: Auto-generated queries
SELECT DISTINCT "users"."id", "users"."name", "users"."email" FROM "users" WHERE "users"."name" LIKE '%john%' ORDER BY "users"."id" ASC LIMIT 10;

SELECT "users"."id", "users"."name", "users"."email" FROM "users" WHERE "users"."id" IN (SELECT "user_friends"."friend_id" FROM "user_friends" WHERE "user_friends"."user_id" = 1);

SELECT "groups"."id", "groups"."name", COUNT(DISTINCT "group_users"."user_id") AS "user_count" FROM "groups" LEFT JOIN "group_users" ON "groups"."id" = "group_users"."group_id" GROUP BY "groups"."id", "groups"."name" HAVING COUNT(DISTINCT "group_users"."user_id") >= 5 ORDER BY "user_count" DESC;

SELECT "users"."id", "users"."name" FROM "users" WHERE "users"."age" >= 18 AND "users"."age" <= 65 AND "users"."status" IN ('active', 'pending') AND NOT ("users"."role" = 'banned') ORDER BY "users"."created_at" DESC LIMIT 20 OFFSET 40;

INSERT INTO "users" ("name", "email", "age", "status") VALUES ('Alice', 'alice@example.com', 30, 'active');

UPDATE "users" SET "name" = 'Bob Updated', "updated_at" = '2024-01-15T12:00:00Z' WHERE "id" = 42;

SELECT "users"."id", "users"."name", "pets"."id" AS "pet_id", "pets"."name" AS "pet_name" FROM "users" LEFT JOIN "pets" ON "users"."id" = "pets"."owner_id" WHERE "users"."id" IN (1, 2, 3) ORDER BY "users"."id" ASC, "pets"."name" ASC;
