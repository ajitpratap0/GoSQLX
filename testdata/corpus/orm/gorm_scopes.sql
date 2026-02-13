-- GORM-style: Scoped queries
SELECT * FROM "users" WHERE "users"."age" > 18 AND "users"."active" = true AND "users"."deleted_at" IS NULL ORDER BY "users"."created_at" DESC LIMIT 25 OFFSET 0;

SELECT COUNT(*) FROM "users" WHERE "users"."age" > 18 AND "users"."active" = true AND "users"."deleted_at" IS NULL;

UPDATE "users" SET "updated_at" = '2024-01-15 10:30:00', "name" = 'John Doe' WHERE "users"."id" = 1 AND "users"."deleted_at" IS NULL;

INSERT INTO "users" ("created_at","updated_at","deleted_at","name","email","age") VALUES ('2024-01-15 10:30:00','2024-01-15 10:30:00',NULL,'Jane Doe','jane@example.com',25);

UPDATE "users" SET "deleted_at" = '2024-01-15 10:30:00' WHERE "users"."id" = 1 AND "users"."deleted_at" IS NULL;
