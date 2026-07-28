# Contributing

Thanks for helping improve `javalin-security`.

## Toolchain

| Tool    | Version                   |
|---------|---------------------------|
| JDK     | 17                        |
| Kotlin  | 2.4                       |
| Javalin | 7.2.x                     |
| Build   | Gradle (wrapper included) |

Dependency versions live in `gradle/libs.versions.toml`.

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

```bash
pip install -r docs/requirements.txt
mkdocs serve
```

- Every code sample has Kotlin **and** Java tabs.
- Prefer snippets adapted from `e2eTest` sources.
- Use admonitions for security-critical notes.

## Submitting changes

1. Fork and branch from `main`.
2. Add or adjust tests for behavior changes.
3. Run `./gradlew build` (and `mkdocs build` for doc changes).
4. Open a pull request.
