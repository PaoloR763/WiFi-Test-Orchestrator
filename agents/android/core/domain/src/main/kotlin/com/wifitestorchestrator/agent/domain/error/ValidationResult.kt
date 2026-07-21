package com.wifitestorchestrator.agent.domain.error

sealed interface ValidationResult<out T : Any>

data class Valid<out T : Any>(val value: T) : ValidationResult<T>

data class Invalid(val error: DomainValidationError) : ValidationResult<Nothing>

inline fun <T : Any, R : Any> ValidationResult<T>.map(transform: (T) -> R): ValidationResult<R> =
    when (this) {
        is Valid -> Valid(transform(value))
        is Invalid -> this
    }

inline fun <T : Any, R : Any> ValidationResult<T>.flatMap(
    transform: (T) -> ValidationResult<R>,
): ValidationResult<R> =
    when (this) {
        is Valid -> transform(value)
        is Invalid -> this
    }
