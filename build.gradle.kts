import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
}

allprojects {
    group = "io.github.mzlnk"
    version = "1.0.0-SNAPSHOT"
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")

    repositories {
        mavenCentral()
    }

    extensions.configure<KotlinJvmProjectExtension> {
        jvmToolchain(17)
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}