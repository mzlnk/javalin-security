dependencies {
    compileOnly(libs.javalin)

    testImplementation(libs.javalin)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockk)
    testRuntimeOnly(libs.junit.platform.launcher)

    e2eTestImplementation(libs.javalin)
    e2eTestImplementation(platform(libs.junit.bom))
    e2eTestImplementation(libs.junit.jupiter)
    e2eTestImplementation(libs.assertj.core)
    e2eTestImplementation(libs.mockk)
    e2eTestRuntimeOnly(libs.junit.platform.launcher)
}
