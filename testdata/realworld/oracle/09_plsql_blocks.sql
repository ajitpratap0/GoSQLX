-- PL/SQL anonymous blocks, routines, triggers and packages as deployment
-- scripts run them through SQL*Plus / SQLcl: each block's inner ';' belong
-- to it, and a "/" line ends it.
BEGIN
  NULL;
END;
/
BEGIN
  DBMS_STATS.GATHER_TABLE_STATS(ownname => 'APP', tabname => 'ORDERS');
END;
/
DECLARE
  v_count NUMBER := 0;
BEGIN
  SELECT COUNT(*) INTO v_count FROM orders WHERE status = 'OPEN';
  IF v_count > 100 THEN
    UPDATE orders SET priority = 'HIGH' WHERE status = 'OPEN';
  ELSIF v_count > 10 THEN
    UPDATE orders SET priority = 'MEDIUM' WHERE status = 'OPEN';
  ELSE
    NULL;
  END IF;
  COMMIT;
END;
/
BEGIN
  FOR r IN (SELECT order_id FROM orders WHERE shipped_at IS NULL) LOOP
    UPDATE order_lines SET state = 'PENDING' WHERE order_id = r.order_id;
  END LOOP;
  COMMIT;
EXCEPTION
  WHEN OTHERS THEN
    ROLLBACK;
    RAISE;
END;
/
DECLARE
  CURSOR c_customers IS SELECT customer_id, email FROM customers WHERE active = 1;
  v_sent PLS_INTEGER := 0;
BEGIN
  FOR c IN c_customers LOOP
    INSERT INTO mail_queue (customer_id, email) VALUES (c.customer_id, c.email);
    v_sent := v_sent + 1;
  END LOOP;
  DBMS_OUTPUT.PUT_LINE('queued ' || v_sent);
END;
/
CREATE OR REPLACE PROCEDURE archive_orders (p_before IN DATE) AS
BEGIN
  INSERT INTO orders_archive SELECT * FROM orders WHERE order_date < p_before;
  DELETE FROM orders WHERE order_date < p_before;
  COMMIT;
END archive_orders;
/
CREATE OR REPLACE FUNCTION order_total (p_order_id IN NUMBER) RETURN NUMBER IS
  v_total NUMBER;
BEGIN
  SELECT SUM(quantity * unit_price) INTO v_total FROM order_lines WHERE order_id = p_order_id;
  RETURN NVL(v_total, 0);
END order_total;
/
CREATE OR REPLACE TRIGGER orders_bi
BEFORE INSERT ON orders
FOR EACH ROW
BEGIN
  IF :NEW.order_id IS NULL THEN
    :NEW.order_id := orders_seq.NEXTVAL;
  END IF;
  :NEW.created_at := SYSTIMESTAMP;
END;
/
CREATE OR REPLACE TRIGGER orders_audit
AFTER UPDATE OF status ON orders
FOR EACH ROW
DECLARE
  v_user VARCHAR2(30) := SYS_CONTEXT('USERENV', 'SESSION_USER');
BEGIN
  INSERT INTO order_audit (order_id, old_status, new_status, changed_by)
  VALUES (:OLD.order_id, :OLD.status, :NEW.status, v_user);
END;
/
CREATE OR REPLACE PACKAGE order_api AS
  PROCEDURE ship (p_order_id IN NUMBER);
  FUNCTION is_shipped (p_order_id IN NUMBER) RETURN BOOLEAN;
END order_api;
/
CREATE OR REPLACE PACKAGE BODY order_api AS
  PROCEDURE ship (p_order_id IN NUMBER) IS
  BEGIN
    UPDATE orders SET status = 'SHIPPED', shipped_at = SYSDATE WHERE order_id = p_order_id;
  END ship;
  FUNCTION is_shipped (p_order_id IN NUMBER) RETURN BOOLEAN IS
    v_status orders.status%TYPE;
  BEGIN
    SELECT status INTO v_status FROM orders WHERE order_id = p_order_id;
    RETURN v_status = 'SHIPPED';
  END is_shipped;
END order_api;
/
BEGIN
  EXECUTE IMMEDIATE 'DROP TABLE tmp_orders';
EXCEPTION
  WHEN OTHERS THEN
    IF SQLCODE != -942 THEN
      RAISE;
    END IF;
END;
/
BEGIN
  order_api.ship(42);
  CASE WHEN order_api.is_shipped(42) THEN DBMS_OUTPUT.PUT_LINE('ok'); ELSE DBMS_OUTPUT.PUT_LINE('not shipped'); END CASE;
END;
/
SELECT order_id, status FROM orders WHERE order_id = 42;
UPDATE orders SET priority = 'LOW' WHERE status = 'SHIPPED';
COMMIT;
