# GoSQLX terminal demo, rendered with VHS (https://github.com/charmbracelet/vhs).
#
# This tape records only the terminal segment (validate, format, lint, about
# 12 seconds). Do not run it directly to refresh the README GIF; run
#
#   .github/assets/build-demo.sh
#
# from the repository root instead. That script runs this tape, then appends
# the playground.png segment (about 3 seconds) to produce the committed
# .github/assets/demo.gif (about 15 seconds in total, 150KB, within the
# 10-15 seconds issue #669 asks for).

Output .github/assets/demo-terminal.gif

Set Shell "bash"
Set FontSize 18
Set Width 960
Set Height 540
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1

# Setup, not shown in the GIF.
Hide
Type "cd .github/assets && clear"
Enter
Show

Type "gosqlx validate demo.sql"
Sleep 400ms
Enter
Sleep 1500ms

Type "gosqlx format demo.sql"
Sleep 400ms
Enter
Sleep 2500ms

Type "clear"
Enter
Type "gosqlx lint demo.sql 2>&1 | grep -E '^\[L' | head -5"
Sleep 400ms
Enter
Sleep 2500ms
