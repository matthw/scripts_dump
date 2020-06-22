#!/bin/sh
# list number of log entries for each asm policies


(
cat << EOF
 SELECT name,log.entries
  FROM PLC.PL_POLICIES as pol,
       ( SELECT policy_id,COUNT(policy_id) AS entries FROM PRX.REQUEST_LOG 
	  WHERE flg_display=1 
                 AND has_violations = 1 
                 AND id > (SELECT IF(request_log_id, request_log_id, 0) FROM PRX.REQUEST_LOG_CLEARED)
		 AND (NOT EXISTS (SELECT log_delete_exist.flg_is_deleted FROM PRX.REQUEST_LOG_PROPERTIES log_delete_exist WHERE log_delete_exist.flg_is_deleted = 1)
		      OR (id NOT IN (SELECT log_delete_ids.request_log_id FROM PRX.REQUEST_LOG_PROPERTIES log_delete_ids WHERE log_delete_ids.flg_is_deleted = 1))
		     )
		GROUP BY policy_id) AS log
   WHERE pol.id = log.policy_id ORDER BY entries DESC
EOF
)| mysql -u root -p$(perl -MF5::Cfg -e 'print F5::Cfg::get_mysql_password(user => q{root})') -t
