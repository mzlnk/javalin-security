# Contributing

Thanks for helping improve `javalin-security`.

## Toolchain

| Tool    | Version                             |
|---------|-------------------------------------|
| JDK     | 17                                  |
| Kotlin  | {{ versions.kotlin_family }} (build) / language & API {{ versions.kotlin_language_family }} (consumer floor) |
| Javalin | {{ versions.javalin_family }}       |
| Build   | Gradle (wrapper included)           |

Dependency versions live in `gradle/libs.versions.toml`; the documentation site reads from
there (and from `gradle.properties`) via `docs/main.py`, so bumping a version in Gradle updates
the docs automatically. Published artifacts use `kotlin-language` / `apiVersion` so Kotlin
**{{ versions.kotlin_language_family }}+** consumers can compile against the library.

## Building and testing

```bash
./gradlew assemble
./gradlew test
./gradlew e2eTest
./gradlew build
./gradlew :dokkaGenerate   # → build/dokka/html
```

## Conventions

- Prefer end-to-end tests with `JavalinTest`; mirror scenarios in Kotlin **and** Java.
- Assert that failure detail never leaks into responses.
- Keep the public surface Java-friendly (`@JvmStatic`, `@JvmField`, `Class`-taking overloads).
- Every public declaration has KDoc.
- Fail fast on unsafe configuration (`SecurityConfigurationException`).

## Documentation

Everything MkDocs-related lives under `docs/`: the config (`docs/mkdocs.yml`), the macros
helper (`docs/main.py`), the Python dependencies (`docs/requirements.txt`), and the markdown
sources (`docs/content/`).

```bash
pip install -r docs/requirements.txt
mkdocs serve -f docs/mkdocs.yml
```

- Every code sample has Kotlin **and** Java tabs.
- Prefer snippets adapted from `e2eTest` sources.
- Use admonitions for security-critical notes.

## Submitting changes

1. Fork and branch from `main`.
2. Add or adjust tests for behavior changes.
3. Run `./gradlew build` (and `mkdocs build -f docs/mkdocs.yml` for doc changes).
4. Open a pull request.
