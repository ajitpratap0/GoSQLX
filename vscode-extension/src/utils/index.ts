/**
 * GoSQLX Extension Utilities
 *
 * This module exports all utility functions and classes used by the extension.
 */

// Validation utilities
export {
    ValidationResult,
    SqlDialect,
    VALID_DIALECTS,
    SQL_LANGUAGE_IDS,
    SQL_FILE_EXTENSIONS,
    validateIndentSize,
    validateDialect,
    validateExecutablePath,
    validateTimeout,
    validateTraceLevel,
    validateConfiguration,
    isSqlLanguageId,
    getSqlFileExtensions,
    extractFileExtension,
    isAbsolutePath,
    normalizeExecutablePath
} from './validation';

// Error messaging utilities
export {
    ErrorContext,
    ERROR_CODES,
    getExecutableNotFoundMessage,
    getLspStartFailureMessage,
    getCommonSetupErrorMessage,
    getConfigurationErrorMessage,
    getValidationErrorMessage,
    getFormatErrorMessage,
    getAnalysisErrorMessage,
    extractErrorCode,
    formatError
} from './errors';

// Telemetry utilities
export {
    TelemetryEventType,
    TelemetryEvent,
    SanitizedTelemetryData,
    TelemetryManager,
    promptTelemetryOptIn,
    withTelemetry
} from './telemetry';

// Performance metrics utilities
export {
    OperationType,
    PerformanceMeasurement,
    OperationStats,
    PerformanceTimer,
    MetricsCollector,
    showMetricsReport,
    createPerformanceStatusBarItem,
    updatePerformanceStatusBar
} from './metrics';
