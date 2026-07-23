dependencies {
    api(project(":javalin-security-jwt"))
    compileOnly(libs.nimbus.jose.jwt)

    testImplementation(libs.javalin)
    testImplementation(libs.nimbus.jose.jwt)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}
