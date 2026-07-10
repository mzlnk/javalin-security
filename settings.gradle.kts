plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "javalin-security"

include("core")

project(":core").name = "javalin-security"