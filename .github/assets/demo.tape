# GoSQLX terminal demo, rendered with VHS (https://github.com/charmbracelet/vhs).
#
# Regenerate from the repository root:
#   go install ./cmd/gosqlx   # puts `gosqlx` on PATH
#   vhs .github/assets/demo.tape
#
# Output: .github/assets/demo.gif (keep it under 5MB, about 12 seconds).

Output .github/assets/demo.gif

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
Sleep 2s

Type "gosqlx format demo.sql"
Sleep 400ms
Enter
Sleep 3s

Type "clear"
Enter
Type "gosqlx lint demo.sql 2>&1 | grep -E '^\[L' | head -5"
Sleep 400ms
Enter
Sleep 3s
