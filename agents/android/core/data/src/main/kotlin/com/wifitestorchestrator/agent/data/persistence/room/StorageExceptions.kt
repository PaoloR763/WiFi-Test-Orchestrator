package com.wifitestorchestrator.agent.data.persistence.room

internal sealed class StorageAccessException : RuntimeException(null, null, false, false)

internal class StorageInitializationException : StorageAccessException()

internal class StorageCorruptionException : StorageAccessException()

internal class StorageSchemaIncompatibleException : StorageAccessException()

internal class StorageMigrationMissingException : StorageAccessException()
