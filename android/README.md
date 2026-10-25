# android — the Android app

**English** · [中文](README.zh.md)

**Status: not started** (planned for milestone **M5**).

This directory will hold the Android client. It is empty today and **contains nothing buildable**.

---

## Planned layout

`
android/
├── app/                      main app (Kotlin + Jetpack Compose)
├── autofill/                 AutofillService module
├── passkey/                  CredentialProviderService (API 34+)
└── core-bindings/            UniFFI-generated Kotlin bindings + .so
`

See `docs/01-需求与架构/02-概要设计.md` §2.2.

---

## Things to confirm before starting

These are Android-specific points where **getting it wrong causes a security incident or data loss**.
Check them off one by one when work starts:

### 1. Permission declarations (the technical basis of the security promise)

`xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />

<!-- deliberately absent: INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE -->
`

**The absence of the `INTERNET` permission is what makes "no network" true.** Android's permission model is a hard constraint here: without it, any socket creation throws `SecurityException`, with no way around it. That is how requirement NFR-SEC-07 lands on Android.

Verify at acceptance time by decompiling: `aapt dump permissions app-release.apk`

### 2. Backup policy (ADR-13)

`xml
<application android:allowBackup="true"
             android:fullBackupContent="@xml/backup_rules"
             android:dataExtractionRules="@xml/data_extraction_rules">
`

| Data | Location | Backed up |
| --- | --- | --- |
| Vault files | `files/vaults/` | ✅ Allowed (ciphertext; restores onto a new device) |
| Logs | `files/logs/` | ❌ Excluded |
| Exports | `files/exports/` | ❌ Excluded |

> ⚠️ **A common misunderstanding worth correcting**: `android:allowBackup` is a **manifest attribute declared by the developer; a user cannot turn it off for a single app in system settings**. What the user can turn off is **device-wide backup** (affecting every app). The app must therefore tell users the truth in-product — see `docs/01-需求与架构/03-详细设计.md` §9.1.

### 3. Biometric keys (must never be backed up)

`kotlin
KeyGenParameterSpec.Builder(alias, ...)
    .setUserAuthenticationRequired(true)
    .setInvalidatedByBiometricEnrollment(true)   // ← invalidated when biometrics change
`

Android Keystore keys are **inherently non-exportable**, which is good: it guarantees key material cannot be carried off by a system backup. **Do not try to export or "back up" the key.**

### 4. Minimum versions and degradation

| Capability | Minimum API | Behaviour on older versions |
| --- | --- | --- |
| Autofill | 26 (Android 8.0) | Feature absent; offer a "copy password" path |
| Passkey | **34 (Android 14)** | Hide the related UI and explain why; passwords and Autofill are unaffected |

---

## Cross-compilation

The Rust core has to be built for Android targets:

`bash
rustup target add aarch64-linux-android armv7-linux-androideabi
`

The build chain (including `cargo-ndk`, UniFFI binding generation and Gradle integration) is described in `docs/01-需求与架构/04-系统设计.md` §5.2.

> The NDK version must be compatible with the Rust target; **lock and record the specific version during M0** — do not pick one from memory.

---

## Related documents

| Topic | Location |
| --- | --- |
| Android implementation notes | `docs/01-需求与架构/03-详细设计.md` §9 |
| Autofill mechanism | `docs/01-需求与架构/02-概要设计.md` §4.5 |
| Passkey mechanism | `docs/01-需求与架构/02-概要设计.md` §4.6 |
| Phase breakdown | `docs/01-需求与架构/04-系统设计.md` §10.1 |
