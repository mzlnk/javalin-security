# javalin-security — Documentation site

## Layout

```
docs/
├── README.md            ← you are here
├── mkdocs.yml           ← MkDocs config (site nav, plugins, theme)
├── main.py              ← macros helper: reads versions from Gradle
├── requirements.txt     ← Python dependencies for the docs build
└── content/             ← docs_dir (all published Markdown + assets)
    ├── index.md
    ├── getting-started/
    ├── concepts/
    ├── extensions/
    ├── guides/
    ├── stylesheets/
    ├── api-reference.md
    ├── contributing.md
    ├── changelog.md
    ├── http-security.md
    └── websocket-security.md
```

Only files under `content/` are served on the site. `README.md`, `mkdocs.yml`, `main.py`, and
`requirements.txt` are build-time artifacts.

## Framework

- [**MkDocs**](https://www.mkdocs.org/) — static-site generator.
- [**Material for MkDocs**](https://squidfunk.github.io/mkdocs-material/) — theme and most of
  the interactive features (tabs, admonitions, code blocks, palette).
- [**mkdocs-macros-plugin**](https://mkdocs-macros-plugin.readthedocs.io/) — enables Jinja
  templating in Markdown. Used here to inject version numbers from Gradle into install
  snippets (see [Version handling](#version-handling)).
- [**PyMdown Extensions**](https://facelessuser.github.io/pymdown-extensions/) — the
  `pymdownx.*` markdown extensions (tabs, superfences, snippets, highlight, …).

Everything is Python; nothing is generated from Node or a JS bundler.

## Prerequisites

- **Python 3.11+** (`main.py` uses the built-in `tomllib`; check with `python3 --version`).
- Optionally: [`uv`](https://docs.astral.sh/uv/) or `pipx` if you prefer managing Python envs
  that way — plain `python -m venv` also works.

The Dokka-generated API reference is a separate concern and lives in `build/dokka/html/` after
`./gradlew :dokkaGenerate`. CI stitches it into `/api/` on the deployed site; see the
[`Generate docs`](../.github/workflows/docs.yml) workflow.

## Run it locally

From the repository root:

```bash
python3 -m venv docs/.venv
source docs/.venv/bin/activate
pip install -r docs/requirements.txt

mkdocs serve -f docs/mkdocs.yml
```

That starts a live-reload server on <http://127.0.0.1:8000>. Edits to any file under
`docs/content/`, `docs/mkdocs.yml`, or `docs/main.py` trigger an automatic rebuild.

The `docs/.venv/` directory is already git-ignored.

### One-shot build (matches CI)

```bash
mkdocs build -f docs/mkdocs.yml --strict
```

`--strict` fails on warnings, broken links, and macro errors. Run it before pushing — the CI
uses the same flag.

### Working from inside `docs/`

If you prefer, `cd docs` first and drop the `-f docs/mkdocs.yml` argument:

```bash
cd docs
mkdocs serve
mkdocs build --strict
```

## Version handling

Install snippets and version tables in `content/` reference variables such as
`{{ versions.library }}`, `{{ versions.javalin }}`, `{{ versions.nimbus_jose_jwt }}`, etc. The
values are computed at build time by `main.py`:

- **Project version** is parsed from the root `gradle.properties` (`version=…`).
- **Dependency versions** are read from `gradle/libs.versions.toml`.
- Convenience families such as `versions.javalin_family` (`7.2.x`), `versions.kotlin_family`
  (build Kotlin, e.g. `2.4`), and `versions.kotlin_language_family` (published language/API /
  consumer floor, e.g. `2.0`) are computed by trimming to `major.minor`.

Bumping a version in Gradle propagates to the docs on the next build — no Markdown edits
required. If you add or remove a key in `libs.versions.toml`, update the `env.variables` map in
`main.py` accordingly; `mkdocs build --strict` in CI will flag any references that fail to
resolve.

## Publishing

GitHub Pages is built and deployed by [`.github/workflows/docs.yml`](../.github/workflows/docs.yml)
on every push to `main` that touches `docs/**`, Gradle files, or source under `**/src/main/**`.
The workflow:

1. Sets up JDK 17 + Python 3.12.
2. Installs `docs/requirements.txt`.
3. Runs `mkdocs build --strict --config-file docs/mkdocs.yml`.
4. Runs `./gradlew :dokkaGenerate` and copies the KDoc HTML under `/api/`.
5. Uploads the combined `site/` as the Pages artifact and deploys it.

## Writing conventions

- **Kotlin + Java tabs** for every code sample.
- **Real, runnable code** — prefer snippets adapted from the `e2eTest` sources in each module
  so examples stay in sync with the library.
- **Admonitions** (`!!! tip`, `!!! warning`, `!!! danger`) for security-critical notes and
  common pitfalls.
- **Relative links** between pages inside `content/` (e.g.
  `[Authorization](../concepts/authorization.md)`). MkDocs rewrites these to the correct site
  URL and `--strict` catches broken ones.
- **Version numbers** — never hardcode; use `{{ versions.* }}` (see above).
- **New pages** must be added to the `nav:` block in `mkdocs.yml`; otherwise Material's
  navigation and the "next / previous" links won't include them.

## Troubleshooting

| Symptom                                             | Likely cause / fix                                                                                     |
|-----------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `ModuleNotFoundError: No module named 'tomllib'`    | Python < 3.11 — install/switch to 3.11+.                                                               |
| `Config value 'plugins': The "macros" plugin is not installed` | You forgot `pip install -r docs/requirements.txt` in your venv.                          |
| `KeyError` from `main.py` at build time             | You referenced `{{ versions.something }}` that is not in the `env.variables` map — add it to `main.py`.|
| A page shows literal `{{ versions.foo }}` text       | The macros plugin didn't process that file (check `on_error_fail: true` in `mkdocs.yml`).             |
| CI passes locally with `mkdocs build` but fails on `--strict` | You have a warning (usually a broken link). Run `mkdocs build --strict` locally first.        |
