# SafeGuardian Android — Private Notes & Vault MVP

This repository contains the first native Android MVP for SafeGuardian, a **local-only encrypted notes and file vault**. The build has a dark, graphite-and-mint interface.

## Features

- Add/edit/delete private text notes.
- Import files through Android's Storage Access Framework.
- Export plaintext copies explicitly to a location chosen by the user.
- Each full record is sealed using AES-256-GCM with a fresh random nonce and a device-bound secret held in the Android Keystore.
- Random on-disk filenames: notes, file names, MIME types and file content are stored together in the encrypted record.
- Screen capture protection on the main activity (`FLAG_SECURE`).
- No INTERNET permission; no networking or analytics SDK.
- Android backup is disabled to prevent unusable cloud backups of device-bound encrypted records.

## Building the debug APK

Open the [Android Actions workflow](https://github.com/SafeGuardian/AnonymousAndroid/actions/workflows/android.yml) or build locally with JDK 17, Android SDK API 35 and Gradle 8.11.1:

```bash
gradle :app:assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`.

## Security limitations — read before using

**This is a prototype, not an audited production vault.** Android Keystore device-bound encryption is **not** a cross-device E2EE scheme and does not provide a recovery key. The app has no master-password verification or biometric gate, and data remains accessible while the device is unlocked and the app is running. Rooted/compromised devices or malicious code running as the same app can obtain plaintext. The current file format contains base64-encoded file data inside encrypted JSON: imports are limited to 8 MiB; it is not suitable for large video files. The filesystem may contain transient data during imports/exports, and exports are **plaintext**. Losing/uninstalling the app permanently loses its records. Do not import irreplaceable or highly sensitive information in this MVP.

**MirageSync is not yet integrated into the Android application.** The separate MirageSync MVP lives under `miragesync/` in the `SafeGuardian/mirage-protocol` repository. The next development step is a reviewed shared cryptographic key hierarchy, authenticated device pairing, and native Android bindings to the sync engine.

## Roadmap

1. Master-password based Argon2id key wrapping and recovery key, plus authentication at unlock.
2. Streaming encrypted files, encrypted full-text index and safe file preview.
3. JNI integration with MirageSync Rust, direct P2P and QUIC relay fallback.
4. Multi-device conflicts, revisions, backup and security review.
