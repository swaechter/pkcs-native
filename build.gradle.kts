import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    id("com.github.johnrengelman.shadow") version ("7.1.0")
    id("org.graalvm.buildtools.native") version ("0.9.27")
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
    gradlePluginPortal()
}

dependencies {
    // PKCS11
    implementation("iaik.pkcs.pkcs11:iaikPkcs11Wrapper:1.6.8")

    // Testing
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}

tasks {
    named<ShadowJar>("shadowJar") {
        archiveFileName.set("native.jar")
        manifest {
            attributes(mapOf("Main-Class" to "fr.devboxsante.cps.nativ.Launcher"))
        }
    }

    build {
        dependsOn(shadowJar)
    }
}

graalvmNative {
    agent {
        defaultMode = "standard"
    }
    binaries {
        named("main") {
            mainClass.set("fr.devboxsante.cps.nativ.Launcher")
            fallback.set(false)
            verbose.set(true)
            useFatJar.set(true)
            imageName.set("native")
        }
    }
    toolchainDetection = false
}
