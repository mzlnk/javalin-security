# Cursor

Install the javalin-security [Cursor Agent Skill](https://cursor.com/docs/skills) so the
Agent can load library guidance on demand when a task matches.

## Setup

1. Create the skill directory — project-scoped (recommended) or personal:

    ```bash
    mkdir -p .cursor/skills/javalin-security   # project
    # mkdir -p ~/.cursor/skills/javalin-security  # personal
    ```

2. Create `SKILL.md` inside that directory (name is case-sensitive) and paste the content
   from the block below. The folder name must be exactly `javalin-security`.
3. Restart Cursor (or reload the workspace) and confirm `javalin-security` appears in the
   Agent skill list (`/`).

## File contents

Copy the block below into `.cursor/skills/javalin-security/SKILL.md`:

````markdown { .ai-paste title="SKILL.md" }
{{ ai_include("cursor/SKILL.md") }}
````
