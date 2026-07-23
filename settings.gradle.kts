plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "javalin-security-root"

include("core")
project(":core").name = "javalin-security"

include("extensions/common")
project(":extensions/common").name = "javalin-security-extensions-common"

include("extensions/jwt")
project(":extensions/jwt").name = "javalin-security-jwt"

include("extensions/jwt-nimbus")
project(":extensions/jwt-nimbus").name = "javalin-security-jwt-nimbus"

include("extensions/jwt-auth0")
project(":extensions/jwt-auth0").name = "javalin-security-jwt-auth0"

include("extensions/basic-auth")
project(":extensions/basic-auth").name = "javalin-security-basic-auth"