# Releasing

Manual releases are performed via the [Release](.github/workflows/release.yml) GitHub Actions workflow.
Only the `mzlnk` GitHub user may dispatch it.

Each successful run:

1. Builds, unit-tests and E2E-tests every module.
2. Publishes and releases the artifacts to Maven Central via the Sonatype Central Portal.
3. Creates a `v<version>` Git tag on the released commit and a matching GitHub Release with
   auto-generated release notes and the module JARs (main, `-sources`, `-javadoc`) plus POMs
   attached as assets. Versions with a pre-release qualifier (for example `1.0.0-rc.1`) are
   marked as pre-releases on GitHub.

## Published artifacts

| Artifact | Module |
|---|---|
| `io.github.mzlnk:javalin-security` | `core` |
| `io.github.mzlnk:javalin-security-jwt` | `extensions/jwt` |
| `io.github.mzlnk:javalin-security-jwt-nimbus` | `extensions/jwt-nimbus` |
| `io.github.mzlnk:javalin-security-jwt-auth0` | `extensions/jwt-auth0` |
| `io.github.mzlnk:javalin-security-basic-auth` | `extensions/basic-auth` |

## Versioning

The release version is read from [`gradle.properties`](gradle.properties):

```properties
group=io.github.mzlnk
version=1.0.0-SNAPSHOT
```

Snapshot versions (`*-SNAPSHOT`) are published to the Central Portal snapshot repository.
Release versions (for example `1.0.0`) are published to Maven Central.

## Release steps

1. Update `version` in `gradle.properties` to the release version (for example `1.0.0`).
2. Commit and push the change to the branch you intend to release from.
3. Make sure no `v<version>` tag already exists for that version (the workflow will refuse
   to run otherwise).
4. In GitHub Actions, open **Release**, select that branch, and run the workflow.
5. Approve the `maven-central` environment deployment when prompted.
6. Verify the new [GitHub Release](https://github.com/mzlnk/javalin-security/releases) and,
   once Maven Central has synced, that the artifacts are available.
7. Bump `version` in `gradle.properties` to the next snapshot (for example `1.0.1-SNAPSHOT`),
   commit, and push.

## GitHub Environment: `maven-central`

Create a protected environment named `maven-central` on the repository and restrict it to
required reviewer `mzlnk`. Store the following secrets on that environment (not as repository secrets):

| Secret | Description |
|---|---|
| `SONATYPE_USERNAME` | Central Portal user-token username (`central.sonatype.com` → Account → Generate User Token) |
| `SONATYPE_PASSWORD` | Central Portal user-token password |
| `SIGNING_KEY` | ASCII-armored PGP private key (full block, including `BEGIN` / `END`) |
| `SIGNING_KEY_ID` | Last 8 hex characters of the key ID |
| `SIGNING_PASSWORD` | Passphrase for the PGP key |

## Local verification

```sh
./gradlew clean assemble test e2eTest
./gradlew publishToMavenLocal
```

Publishing locally requires the same signing properties (`signingInMemoryKey`,
`signingInMemoryKeyId`, `signingInMemoryKeyPassword`) unless you temporarily disable signing
for a local experiment.
