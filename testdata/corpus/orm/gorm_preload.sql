-- GORM-style: Preload associations (auto-generated)
SELECT * FROM "users" WHERE "users"."deleted_at" IS NULL;

SELECT * FROM "profiles" WHERE "profiles"."user_id" IN (1,2,3,4,5) AND "profiles"."deleted_at" IS NULL;

SELECT * FROM "orders" WHERE "orders"."user_id" IN (1,2,3,4,5) AND "orders"."deleted_at" IS NULL ORDER BY "orders"."created_at" DESC;

SELECT * FROM "order_items" WHERE "order_items"."order_id" IN (10,11,12,13,14,15) AND "order_items"."deleted_at" IS NULL;
