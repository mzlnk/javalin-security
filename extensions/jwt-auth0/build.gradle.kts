dependencies {
    api(project(":javalin-security-jwt"))
    compileOnly(libs.auth0.java.jwt)
    compileOnly(libs.auth0.jwks.rsa)

    testImplementation(libs.javalin)
    testImplementation(libs.auth0.java.jwt)
    testImplementation(libs.auth0.jwks.rsa)
    testImplementation(libs.nimbus.jose.jwt)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}
