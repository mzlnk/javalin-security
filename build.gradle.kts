import org.gradle.plugins.ide.idea.model.IdeaModel
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    // Applied (not `apply false`) so the root project acts as the Dokka multi-module aggregator.
    alias(libs.plugins.dokka)
}

allprojects {
    group = "io.github.mzlnk"
    version = "1.0.0-SNAPSHOT"
}

// The root project is the Dokka aggregator and must be able to resolve Dokka's own
// plugins (dokka-base, templating-plugin). Subprojects declare their repositories in the
// `subprojects {}` block below; the root needs its own.
repositories {
    mavenCentral()
}

// ── Dokka multi-module API reference ───────────────────────────────────────
//
// Each subproject applies the Dokka plugin (see the `subprojects {}` block below) and is
// registered here for aggregation. `./gradlew :dokkaGenerate` produces a single HTML site at
// `build/dokka/html`, which the docs pipeline publishes under `/api` on GitHub Pages.
dependencies {
    dokka(project(":javalin-security"))
    dokka(project(":javalin-security-common"))
    dokka(project(":javalin-security-jwt"))
    dokka(project(":javalin-security-jwt-nimbus"))
    dokka(project(":javalin-security-jwt-auth0"))
    dokka(project(":javalin-security-basic-auth"))
}

dokka {
    // Rendered as the title of the aggregated API reference site.
    moduleName.set("javalin-security API")
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "org.jetbrains.dokka")
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