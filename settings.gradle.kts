plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "javalin-security"

include("core")
project(":core").name = "javalin-security"

include("extensions/common")
project(":extensions/common").name = "javalin-security-extensions-common"

include("extensions/jwt")
project(":extensions/jwt").name = "javalin-security-jwt"

include("extensions/basic-auth")
project(":extensions/basic-auth").name = "javalin-security-basic-auth"