// PlatformSecurity — biometric gate, app-switcher redaction, capture detection.
// Build Spec §6. NOT YET IMPLEMENTED.
//
// Next session builds here:
//   * LAContext.evaluatePolicy(.deviceOwnerAuthentication) gate before any reveal
//   * app-switcher snapshot cover on scenePhase .inactive/.background
//   * UIScreen.capturedDidChangeNotification → force re-mask, block reveal
//   * UIApplication.userDidTakeScreenshotNotification → warn
//   * state-restoration disabled on any screen that can hold a credential
//
// This file exists only so SwiftPM has a source file for the target.
enum PlatformSecurityPlaceholder {}
