# AGENTS.md

Give coding agents a durable, repo-local reference for javalin-security by adding an
`AGENTS.md` file at the root of your application repository.

## Setup

1. Create `AGENTS.md` at the repository root (or append to an existing one).
2. Paste the content from the block below.

Many agents auto-discover `AGENTS.md` at the project root. After upgrading
javalin-security, refresh the version and wiring snippets in that file.

## File contents

Copy the block below into your `AGENTS.md`:

````markdown { .ai-paste title="AGENTS.md" }
{{ ai_include("AGENTS.md") }}
````
