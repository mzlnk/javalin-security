import com.vanniktech.maven.publish.MavenPublishBaseExtension
import kotlinx.kover.gradle.plugin.dsl.KoverProjectExtension
import org.gradle.plugins.ide.idea.model.IdeaModel
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.dokka)
    alias(libs.plugins.vanniktech.maven.publish) apply false
    alias(libs.plugins.kover)
}

allprojects {
    group = providers.gradleProperty("group").get()
    version = providers.gradleProperty("version").get()
}

repositories {
    mavenCentral()
}

dependencies {
    dokka(project(":javalin-security"))
    dokka(project(":javalin-security-jwt"))
    dokka(project(":javalin-security-jwt-nimbus"))
    dokka(project(":javalin-security-jwt-auth0"))
    dokka(project(":javalin-security-basic-auth"))
    dokka(project(":javalin-security-api-key"))
    dokka(project(":javalin-security-opaque-token"))
}

dokka {
    moduleName.set("javalin-security API")
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "org.jetbrains.dokka")
    apply(plugin = "idea")
    apply(plugin = "org.jetbrains.kotlinx.kover")

    configure<KoverProjectExtension> {
        currentProject {
            sources {
                includedSourceSets.add("main")
            }
        }
    }

    rootProject.dependencies {
        add("kover", this@subprojects)
    }

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

val publishedProjects = setOf(
    "javalin-security",
    "javalin-security-jwt",
    "javalin-security-jwt-nimbus",
    "javalin-security-jwt-auth0",
    "javalin-security-basic-auth",
    "javalin-security-api-key",
    "javalin-security-opaque-token",
)

configure(subprojects.filter { it.name in publishedProjects }) {
    apply(plugin = "com.vanniktech.maven.publish")

    configure<MavenPublishBaseExtension> {
        publishToMavenCentral(automaticRelease = true)
        signAllPublications()

        coordinates(group.toString(), project.name, version.toString())

        pom {
            name.set(project.name)
            description.set("Security extensions for the Javalin web framework.")
            url.set("https://github.com/mzlnk/javalin-security")
            inceptionYear.set("2026")
            licenses {
                license {
                    name.set("The Apache License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    distribution.set("repo")
                }
            }
            developers {
                developer {
                    id.set("mzlnk")
                    name.set("mzlnk")
                    url.set("https://github.com/mzlnk")
                }
            }
            scm {
                url.set("https://github.com/mzlnk/javalin-security")
                connection.set("scm:git:git://github.com/mzlnk/javalin-security.git")
                developerConnection.set("scm:git:ssh://git@github.com/mzlnk/javalin-security.git")
            }
        }
    }
}
