export {
  CanaryScanner,
  normalize,
  type ScanResult,
  type ScanMetadata,
  type CanaryConfig,
  type CalibrationResult,
} from "./scanner";

export {
  isEnabled as telemetryEnabled,
  setConsent as setTelemetryConsent,
  recordScan,
} from "./telemetry";
