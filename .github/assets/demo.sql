select u.id,u.name,count(o.id) as orders from users u join orders o on o.user_id=u.id where u.active=true group by u.id,u.name having count(o.id)>5 order by orders desc limit 10;
