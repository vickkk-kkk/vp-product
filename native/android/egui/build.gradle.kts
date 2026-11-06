plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}
providers.gradleProperty("vpBuildDir").orNull?.let {
    layout.buildDirectory.set(file("$it/../runtime-build"))
}

val productRoot = projectDir.resolve("../../..").canonicalFile
val sharedHost = productRoot.resolve("flutter/packages/vp_runtime_android/android/src/main/kotlin/org/vp/product/runtime")
val requiredSharedHostFiles = listOf("VpVpnService.kt", "NativeRuntime.kt", "NotificationPublication.kt", "RuntimeIdentity.kt")
val staged = layout.buildDirectory.dir("generated/eguiHost")
val stageHost by tasks.registering(Sync::class) {
    doFirst {
        val missing = requiredSharedHostFiles.filterNot { sharedHost.resolve(it).isFile }
        check(missing.isEmpty()) { "Missing Android runtime host sources: ${missing.joinToString()}; use a complete product checkout." }
    }
    from(projectDir) { include("HostState.kt", "EguiVpnBridge.kt", "EguiVpnConsentActivity.kt") }
    from(sharedHost) { include(*requiredSharedHostFiles.toTypedArray()) }
    into(staged)
}

android {
    namespace = "org.vp.product.runtime"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
    sourceSets["main"].manifest.srcFile("AndroidManifest.xml")
    sourceSets["main"].java.srcDir(staged)
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
tasks.configureEach {
    if (name == "preBuild" || name.startsWith("compile") && name.endsWith("Kotlin")) dependsOn(stageHost)
}
