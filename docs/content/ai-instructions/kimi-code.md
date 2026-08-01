# Kimi Code

Install the javalin-security [Kimi Code skill](https://moonshotai.github.io/kimi-code/en/customization/skills.html)
so Kimi can load library guidance on demand (`/skill:javalin-security` or when the task matches).

## Setup

1. Create the skill directory — project-scoped (recommended) or personal:

    ```bash
    mkdir -p .kimi-code/skills/javalin-security   # project (Kimi-specific)
    # mkdir -p .agents/skills/javalin-security       # project (cross-agent)
    # mkdir -p ~/.kimi-code/skills/javalin-security  # personal (Kimi-specific)
    # mkdir -p ~/.agents/skills/javalin-security     # personal (cross-agent)
    ```

2. Create `SKILL.md` inside that directory (name is case-sensitive) and paste the content
   from the block below. The folder name must be exactly `javalin-security` and match the
   `name` in the frontmatter.
3. Restart Kimi Code from the project directory and confirm `/skill:javalin-security`
   appears in the `/` menu.

## File contents

Copy the block below into `.kimi-code/skills/javalin-security/SKILL.md`:

````markdown { .ai-paste title="SKILL.md" }
{{ ai_include("kimi-code/SKILL.md") }}
````
