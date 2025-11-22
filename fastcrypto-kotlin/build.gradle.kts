plugins {
    kotlin("multiplatform") version "1.9.20"
}

repositories {
    mavenCentral()
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
            systemProperty("java.library.path", file("../target/release").absolutePath)
            systemProperty("jna.library.path", file("../target/release").absolutePath)
        }
    }

    // For now, we focus on JVM. Native targets can be added later.
    // linuxX64("native")

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("net.java.dev.jna:jna:5.14.0")
                // implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting
        val jvmTest by getting
    }
}

tasks.register<Exec>("buildRust") {
    workingDir = file("rust")
    commandLine("cargo", "build", "--release")
}

tasks.named("jvmProcessResources") {
    dependsOn("buildRust")

    doLast {
        // Copy the dylib/so/dll to the resources folder so it can be loaded
        val osName = System.getProperty("os.name").lowercase()
        val libName = if (osName.contains("win")) {
            "fastcrypto_uniffi.dll"
        } else if (osName.contains("mac")) {
            "libfastcrypto_uniffi.dylib"
        } else {
            "libfastcrypto_uniffi.so"
        }

        // Since the crate is part of the workspace, the target directory is in the root
        val source = file("../target/release/$libName")
        if (source.exists()) {
            // Copy to resources for both main and test so it's picked up
            val destMain = file("build/classes/kotlin/jvm/main")
            destMain.mkdirs()
            source.copyTo(File(destMain, libName), overwrite = true)

            val destTest = file("build/classes/kotlin/jvm/test")
            destTest.mkdirs()
            source.copyTo(File(destTest, libName), overwrite = true)

            println("Copied $libName to $destMain and $destTest")
        } else {
            println("Warning: $libName not found at $source")
        }
    }
}
