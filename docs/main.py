"""MkDocs macros: expose project + dependency versions to the docs.

Values are read straight from the Gradle build so the docs never drift from
the actual artifacts. Referenced from ``mkdocs.yml`` via the
``mkdocs-macros-plugin`` (default ``module_name: main``).

Available in Markdown as::

    {{ versions.library }}          # project version, from build.gradle.kts
    {{ versions.javalin }}          # from gradle/libs.versions.toml
    {{ versions.javalin_family }}   # major.minor + ".x" (e.g. "7.2.x")
    {{ versions.kotlin }}
    {{ versions.kotlin_family }}    # major.minor (e.g. "2.4")
    {{ versions.slf4j }}
    {{ versions.nimbus_jose_jwt }}
    {{ versions.auth0_java_jwt }}
    {{ versions.auth0_jwks_rsa }}
    {{ versions.junit_bom }}
    {{ versions.assertj }}
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

# `main.py` lives at `docs/main.py`; Gradle sources sit two levels up at the
# repository root.
_ROOT = Path(__file__).resolve().parent.parent
_BUILD_GRADLE_KTS = _ROOT / "build.gradle.kts"
_LIBS_VERSIONS_TOML = _ROOT / "gradle" / "libs.versions.toml"

# Matches `version = "..."` in the root build.gradle.kts.
_PROJECT_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"', re.MULTILINE)


def _project_version() -> str:
    text = _BUILD_GRADLE_KTS.read_text(encoding="utf-8")
    match = _PROJECT_VERSION_RE.search(text)
    if not match:
        raise RuntimeError(
            f'Could not find `version = "…"` in '
            f"{_BUILD_GRADLE_KTS.relative_to(_ROOT)}."
        )
    return match.group(1)


def _dependency_versions() -> dict[str, str]:
    with _LIBS_VERSIONS_TOML.open("rb") as fh:
        catalog = tomllib.load(fh)
    return dict(catalog.get("versions", {}))


def _family(version: str, *, parts: int, suffix: str = "") -> str:
    """Return a `major.minor(.x)` family string for a full semver-ish version."""
    head = ".".join(version.split(".")[:parts])
    return f"{head}{suffix}"


def define_env(env):
    """Publish `versions.*` variables to the docs."""
    library = _project_version()
    deps = _dependency_versions()

    env.variables["versions"] = {
        "library": library,
        "javalin": deps["javalin"],
        "javalin_family": _family(deps["javalin"], parts=2, suffix=".x"),
        "kotlin": deps["kotlin"],
        "kotlin_family": _family(deps["kotlin"], parts=2),
        "slf4j": deps["slf4j"],
        "nimbus_jose_jwt": deps["nimbus-jose-jwt"],
        "auth0_java_jwt": deps["auth0-java-jwt"],
        "auth0_jwks_rsa": deps["auth0-jwks-rsa"],
        "junit_bom": deps["junit-bom"],
        "assertj": deps["assertj"],
    }
