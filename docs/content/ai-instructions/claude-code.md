# Claude Code

Install the javalin-security [Claude Code skill](https://code.claude.com/docs/en/skills)
so Claude can load library guidance on demand (`/javalin-security` or when the task matches).

## Setup

1. Create the skill directory — project-scoped (recommended) or personal:

    ```bash
    mkdir -p .claude/skills/javalin-security   # project
    # mkdir -p ~/.claude/skills/javalin-security  # personal
    ```

2. Create `SKILL.md` inside that directory (name is case-sensitive) and paste the content
   from the block below. The folder name must be exactly `javalin-security`.
3. Restart Claude Code (or start a new session) and confirm `/javalin-security` appears in
   `/help`.

## File contents

Copy the block below into `.claude/skills/javalin-security/SKILL.md`:

````markdown { .ai-paste title="SKILL.md" }
{{ ai_include("claude-code/SKILL.md") }}
````
