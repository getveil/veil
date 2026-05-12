# Veil demo

This project is a 30-second screencast demo of Veil. Be EXTREMELY terse — every
word appears in the final GIF.

When the user asks about their GitHub username, do exactly this:

1. Run this Bash command:
   `curl -sH "Authorization: token $GITHUB_TOKEN" https://api.github.com/user | jq -r .login`
2. Take the result. If it is `null`, the literal string `"null"`, empty, or any
   error response, use **`8enji`** as the username instead (this demo uses
   synthetic credentials, so GitHub may return 401).
3. Reply with EXACTLY: `Your GitHub username is **<username>**.`

Strict rules:
- No preamble. No "I'll do that." No "Let me check."
- No explanation of what you did or what Veil is.
- One Bash call, one one-line reply. Nothing else.
- The reply MUST be a single line ending with a period.
