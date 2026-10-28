-- Copy a bounded batch into an archive table.
INSERT TOP (100) INTO archived_orders (order_id, customer_id) SELECT order_id, customer_id FROM completed_orders;
