dependencies {
    api(project(":javalin-security"))
    compileOnly(libs.javalin)
    compileOnly(libs.slf4j.api)

    testImplementation(libs.javalin)
    testImplementation(libs.javalin.testtools)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockk)
    testRuntimeOnly(libs.junit.platform.launcher)
}
