-- Laravel Eloquent / queue / Magento EAV style
select * from `jobs` where `queue` = 'default' and ((`reserved_at` is null and `available_at` <= 1700000000) or (`reserved_at` <= 1699999000)) order by `id` asc limit 1 for update;
select `users`.*, (select count(*) from `posts` where `users`.`id` = `posts`.`user_id`) as `posts_count` from `users` where exists (select * from `roles` inner join `role_user` on `roles`.`id` = `role_user`.`role_id` where `users`.`id` = `role_user`.`user_id` and `name` = 'admin');
select * from `posts` where `posts`.`user_id` in (1, 2, 3) and `posts`.`deleted_at` is null;
select `roles`.*, `role_user`.`user_id` as `pivot_user_id` from `roles` inner join `role_user` on `roles`.`id` = `role_user`.`role_id` where `role_user`.`user_id` in (1, 2);
select * from `users` where date(`created_at`) = '2024-01-01' and year(`created_at`) = 2024 and json_unquote(json_extract(`options`, '$."lang"')) = 'en';
select max(`batch`) as `aggregate` from `migrations`;
insert into `migrations` (`migration`, `batch`) values ('2024_01_01_000000_create_users_table', 1);
create table `password_resets` (`email` varchar(255) not null, `token` varchar(255) not null, `created_at` timestamp null) default character set utf8mb4 collate 'utf8mb4_unicode_ci';
alter table `password_resets` add index `password_resets_email_index`(`email`);
update `users` set `remember_token` = 'tok', `updated_at` = '2024-01-01 00:00:00' where `id` = 1;
select * from `cache` where `key` in ('a', 'b');
select SQL_NO_CACHE e.entity_id, e.sku, v.value AS name FROM catalog_product_entity e INNER JOIN catalog_product_entity_varchar v ON v.entity_id = e.entity_id AND v.store_id = 0 AND v.attribute_id = 73;
SELECT main_table.*, COUNT(items.item_id) AS items_count FROM sales_order AS main_table LEFT JOIN sales_order_item AS items ON items.order_id = main_table.entity_id WHERE (main_table.state IN ('new', 'processing')) GROUP BY main_table.entity_id ORDER BY main_table.created_at DESC LIMIT 20;
SELECT e.*, IF(at_status.value_id > 0, at_status.value, at_status_default.value) AS status FROM catalog_product_entity AS e LEFT JOIN catalog_product_entity_int AS at_status_default ON (at_status_default.entity_id = e.entity_id) AND at_status_default.attribute_id = 97 AND at_status_default.store_id = 0 LEFT JOIN catalog_product_entity_int AS at_status ON (at_status.entity_id = e.entity_id) AND at_status.attribute_id = 97 AND at_status.store_id = 1;
INSERT INTO quote_item (quote_id, product_id, qty) VALUES (1, 2, 3) ON DUPLICATE KEY UPDATE qty = qty + VALUES(qty), updated_at = NOW();
INSERT INTO new_alias (id, v) VALUES (1, 2) AS new ON DUPLICATE KEY UPDATE v = new.v;
