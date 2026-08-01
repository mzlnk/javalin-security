# Codex

Install the javalin-security [Codex skill](https://developers.openai.com/codex/skills) so
Codex can load library guidance on demand (`$javalin-security` or when the task matches).

## Setup

1. Create the skill directory — project-scoped (recommended) or personal:

    ```bash
    mkdir -p .agents/skills/javalin-security   # project
    # mkdir -p ~/.codex/skills/javalin-security   # personal (Codex)
    # mkdir -p ~/.agents/skills/javalin-security  # personal (cross-agent)
    ```

2. Create `SKILL.md` inside that directory (name is case-sensitive) and paste the content
   from the block below. The folder name must be exactly `javalin-security` and match the
   `name` in the frontmatter.
3. Restart Codex (or start a new CLI session) and confirm `javalin-security` appears in
   `/skills`.

## File contents

Copy the block below into `.agents/skills/javalin-security/SKILL.md`:

````markdown { .ai-paste title="SKILL.md" }
{{ ai_include("codex/SKILL.md") }}
````
