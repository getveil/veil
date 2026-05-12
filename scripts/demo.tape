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
Set TypingSpeed 50ms

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
Set TypingSpeed 50ms

# --- Demo ---

# Each narration: hide the typed `say "..."` (TypingSpeed 0 → instant),
# Show resumes after Enter so frames capture the cyan animation only.
Hide
Set TypingSpeed 0
Type `say "Your project has a GitHub token the AI agent shouldn't see:"`
Enter
Show
Sleep 3200ms
Set TypingSpeed 50ms

Type "cat .env"
Enter
Sleep 2600ms

Hide
Set TypingSpeed 0
Type `say "Veil moves it into the OS keychain, leaves a format-aware placeholder:"`
Enter
Show
Sleep 3800ms
Set TypingSpeed 50ms

Type "veil init --yes"
Enter
Sleep 3000ms

Hide
Set TypingSpeed 0
Type `say "Inspect what's managed — names, hosts, and last-injected status:"`
Enter
Show
Sleep 3700ms
Set TypingSpeed 50ms

Type "veil list"
Enter
Sleep 3000ms

# Load placeholders into the parent shell env so veil run can re-inject them
# for the agent (claude). Hidden + line-erased.
Hide
Set TypingSpeed 0
Type `set -a && . ./.env && set +a && printf '\033[2K\r\033[1A\033[2K\r'`
Enter
Show
Set TypingSpeed 50ms

Hide
Set TypingSpeed 0
Type `say "Now open Claude Code through Veil:"`
Enter
Show
Sleep 4000ms
Set TypingSpeed 50ms

Type "veil run -- claude --dangerously-skip-permissions"
Enter
Sleep 4500ms

# Brief pause so the viewer registers Claude's TUI before typing
Sleep 800ms

# Type the question deliberately — feels like a person, not pasted
Set TypingSpeed 55ms
Type "What's my GitHub username?"
Set TypingSpeed 50ms
Sleep 700ms
Enter

# Wait for Claude to reason, call the tool, get the response, render.
# CLAUDE.md keeps responses tight (~5-9s). If a particular take is slower,
# bump this and re-record.
Sleep 9000ms

# Pause 4 seconds after the response so viewers can read it
Sleep 4000ms

# Exit Claude with Ctrl+C twice (first asks for confirm, second exits)
Ctrl+C
Sleep 700ms
Ctrl+C
Sleep 2500ms

Hide
Set TypingSpeed 0
Type `say "Veil swapped in the real token on the wire — see the audit log:"`
Enter
Show
Sleep 3700ms
Set TypingSpeed 50ms

Type "veil log --since 1m --host api.github.com"
Enter
Sleep 8000ms
