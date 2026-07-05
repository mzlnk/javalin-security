plugins {
    kotlin("jvm") version "2.4.0"
}

group = "io.github.mzlnk"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("io.javalin:javalin:7.2.2")

    testImplementation("io.javalin:javalin:7.2.2")
    testImplementation("io.javalin:javalin-testtools:7.2.2")
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.3")
    testImplementation("io.mockk:mockk:1.14.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(25)
}

tasks.test {
    useJUnitPlatform()
}