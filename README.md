# SafeGuardian Android v0.2 — encrypted personal workspace

Native Android application (API 26+) with Notes, encrypted Vault and Secrets.

## Implemented in the v0.2 development branch

- Master-password protected random vault key: PBKDF2-HMAC-SHA256 (600,000 iterations), AES-256-GCM authenticated key wrapping.
- Optional **strong** fingerprint/biometric key-wrap via Android Keystore and BiometricPrompt CryptoObject. The biometric key requires authentication per operation.
- Vault auto-locks when the application moves to background and blocks screenshots with FLAG_SECURE.
- Encrypted Markdown text notes with title search, favourites and editing.
- Encrypted file import/export through Android's Storage Access Framework; stream files in AES-256-GCM authenticated 64 KiB chunks, up to 1 GiB, with random file IDs and encrypted metadata.
- Password manager: website, username, password, Android package, additional notes; all stored in authenticated encrypted records.
- SecureRandom-based password generator, 12–128 characters.
- RFC 6238 TOTP for Base32 or otpauth:// URI (SHA1/SHA256/SHA512, 6 or 8 digits, configurable period).
- Android AutofillService for **native Android apps only**, explicitly enabled by the user, requiring fresh master-password or strong biometric unlock and explicit account selection. Only an exact saved Android application package match is offered.
- Clipboard secrets marked sensitive, automatically cleared after 30 seconds if unchanged.
- Migration of v0.1 AES-GCM encrypted records into v0.2 password-protected key storage on first unlock.

## Build

Open the GitHub Actions workflow or build with JDK 17, Android SDK API 35 and Gradle 8.11.1:

```sh
gradle --no-daemon :app:assembleDebug
gradle --no-daemon :app:testDebugUnitTest
```

The debug APK is at `app/build/outputs/apk/debug/app-debug.apk`.

## Security and functional limitations

**Experimental, not independently audited. Do not store irreplaceable passwords or files until secure recovery and backup are available.** Master-password recovery is not yet implemented. Forgotten password or lost phone can permanently lock out all data. Android backup is disabled. Files exported through SAF are unencrypted copies. Large decrypted file outputs are streamed to a user-chosen destination, so if integrity verification fails after output begins, incomplete plaintext may be left at that destination.

PBKDF2 was chosen for stock Android compatibility; an audited Argon2id key-derivation migration and independent crypto review are recommended before production. Biometric key invalidation may require master password after fingerprint changes. Changing the password rewraps the same data key; the biometric key remains tied to that key.

No network permission, no MirageSync integration or cloud storage in this build. The MirageSync Linux/Windows prototypes remain separate. Android Autofill is deliberately restricted: it does not offer to fill browser pages because safe website-to-credential association requires verified origins/Digital Asset Links. Android Autofill is not Passkeys/Credential Manager, and auto-save of credentials from other apps is not enabled.

Files imported in v0.1 used base64 payloads inside authenticated encrypted records and remain readable; new large files use streaming format SGF3. The prototype does not yet include folders, OCR, multi-device sync, encrypted backups, passkeys, desktop clients, or background file watching.

## Test plan

1. Create a master password of at least 12 characters and save several notes and credentials.
2. Force-close the app; verify a password is needed to reopen.
3. Enable fingerprint in settings; lock the app; confirm successful biometric unlock and password fallback.
4. Enter the RFC 6238 sample secret and verify TOTP matches a standard authenticator.
5. Import a multi-megabyte PDF and image, then export each and compare SHA-256.
6. Enable SafeGuardian Autofill in Android settings, bind a credential to a test native package and verify a prompt before autofill.
7. Upgrade a test installation of v0.1 and verify old notes and files are still available after key migration.
