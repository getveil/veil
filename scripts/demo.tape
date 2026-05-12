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
# define a `say` helper that prints colored narration, clean prompt. None
# of this appears in the recording.
Hide
Type "cd $VEIL_DEMO_DIR && unset VEIL_DEMO_DIR"
Enter
Type `veil() { $VEIL_BIN "$@"; }`
Enter
Type `say() { printf '\033[1A\033[2K\r\033[1;36m▸ %s\033[0m\n' "$*"; }`
Enter
Type `export PS1='\[\033[1;32m\]$\[\033[0m\] '`
Enter
Type "clear"
Enter
Show

# --- Demo ---

Type `say "Your project has secrets the AI agent shouldn't see:"`
Sleep 600ms
Enter
Sleep 400ms

Type "cat .env"
Enter
Sleep 1800ms

Type `say "Veil migrates them into the OS keychain and leaves format-aware placeholders:"`
Sleep 600ms
Enter
Sleep 400ms

Type "veil init --yes"
Enter
Sleep 2000ms

Type "cat .env"
Enter
Sleep 2500ms

# Load placeholders into the shell env so the visible command below can
# reference $GITHUB_TOKEN directly. The trailing printf erases the typed
# line so the env-loading isn't part of the demo's visible flow.
Hide
Type `set -a && . ./.env && set +a && printf '\033[2K\r\033[1A\033[2K\r'`
Enter
Show

Type `say "Now watch Veil block a leak — the agent tries to send the GitHub token to the wrong host:"`
Sleep 600ms
Enter
Sleep 400ms

Type `veil run -- curl -s -H "Authorization: token $GITHUB_TOKEN" https://httpbin.org/headers`
Enter
Sleep 2800ms

Type `say "Every block (and injection) is logged locally:"`
Sleep 600ms
Enter
Sleep 400ms

Type "veil log --since 1m"
Enter
Sleep 3000ms
