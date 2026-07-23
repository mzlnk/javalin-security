import org.gradle.plugins.ide.idea.model.IdeaModel
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
    apply(plugin = "idea")

    repositories {
        mavenCentral()
    }
    
    extensions.configure<KotlinJvmProjectExtension> {
        jvmToolchain(17)
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }

    val sourceSets = the<SourceSetContainer>()

    val e2eTest = sourceSets.create("e2eTest") {
        compileClasspath += sourceSets["main"].output
        runtimeClasspath += sourceSets["main"].output
    }

    configurations["e2eTestImplementation"].extendsFrom(configurations["implementation"])
    configurations["e2eTestRuntimeOnly"].extendsFrom(configurations["runtimeOnly"])

    tasks.register<Test>("e2eTest") {
        description = "Runs end-to-end tests."
        group = "verification"
        testClassesDirs = e2eTest.output.classesDirs
        classpath = e2eTest.runtimeClasspath
        shouldRunAfter(tasks.named("test"))
    }

    configure<IdeaModel> {
        module {
            testSources.from(file("src/e2eTest/java"))
            testSources.from(file("src/e2eTest/kotlin"))
            testResources.from(e2eTest.resources.srcDirs)
        }
    }
}