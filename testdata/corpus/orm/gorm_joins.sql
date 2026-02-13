-- GORM-style: Auto-generated JOINs
SELECT "users"."id","users"."created_at","users"."updated_at","users"."deleted_at","users"."name","users"."email","users"."age" FROM "users" LEFT JOIN "profiles" ON "profiles"."user_id" = "users"."id" WHERE "users"."deleted_at" IS NULL AND "profiles"."verified" = true;

SELECT "users"."id","users"."name",COUNT("orders"."id") AS order_count FROM "users" LEFT JOIN "orders" ON "orders"."user_id" = "users"."id" WHERE "users"."deleted_at" IS NULL GROUP BY "users"."id" HAVING COUNT("orders"."id") > 5;

SELECT "users"."id","users"."name","Company"."name" AS "CompanyName" FROM "users" JOIN "companies" AS "Company" ON "Company"."id" = "users"."company_id" WHERE "users"."deleted_at" IS NULL AND "Company"."active" = true ORDER BY "users"."name" ASC LIMIT 50 OFFSET 100;
