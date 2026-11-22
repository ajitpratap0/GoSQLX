-- Application queries with hash comments, adjacent openers, and quoted hashes.
# Application report; this semicolon is part of the comment
SELECT a FROM t WHERE x = 1 # keep both predicates; AND ignored here
AND y = 2;
SELECT a FROM t # trailing comment
;
SELECT 1#no space before comment
;
SELECT '#' AS marker, `a#b` FROM t;
