package com.wifitestorchestrator.agent.data.persistence

enum class LocalPersistenceError {
    INITIALIZATION_FAILED,
    STATE_INCOMPLETE,
    STATE_CONFLICT,
    CONSTRAINT_VIOLATION,
    IO,
    DATABASE_BUSY_OR_LOCKED,
    CORRUPTION,
    SCHEMA_INCOMPATIBLE,
    MIGRATION_MISSING,
    UNKNOWN,
}
