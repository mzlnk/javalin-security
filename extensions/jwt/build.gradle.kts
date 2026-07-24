dependencies {
    api(project(":javalin-security"))
    api(project(":javalin-security-common"))
    compileOnly(libs.javalin)
    compileOnly(libs.slf4j.api)

    testImplementation(libs.javalin)
    testImplementation(libs.javalin.testtools)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockk)
    testRuntimeOnly(libs.junit.platform.launcher)

    e2eTestImplementation(libs.javalin)
    e2eTestImplementation(libs.javalin.testtools)
    e2eTestImplementation(platform(libs.junit.bom))
    e2eTestImplementation(libs.junit.jupiter)
    e2eTestImplementation(libs.assertj.core)
    e2eTestImplementation(libs.mockk)
    e2eTestRuntimeOnly(libs.junit.platform.launcher)
}
