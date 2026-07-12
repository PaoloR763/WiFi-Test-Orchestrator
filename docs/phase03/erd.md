# ERD de Fase 03

```mermaid
erDiagram
    USER ||--o{ USER_ROLE : has
    ROLE ||--o{ USER_ROLE : assigned
    ROLE ||--o{ ROLE_PERMISSION : groups
    PERMISSION ||--o{ ROLE_PERMISSION : grants
    USER ||--o{ SESSION : owns
    SESSION ||--o{ REFRESH_TOKEN : rotates
    REFRESH_TOKEN o|--o| REFRESH_TOKEN : replaces
    USER o|--o{ AUDIT_LOG : acts
    DEVICE o|--o{ AGENT : hosts
    TEST_DEFINITION o|--o{ CAMPAIGN : references
    CAMPAIGN o|--o{ EXECUTION : groups
    AGENT o|--o{ EXECUTION : observes
    EXECUTION ||--o{ METRIC : contains
    EXECUTION ||--o{ ARTIFACT : references
    USER o|--o{ ENROLLMENT_TOKEN : creates
```

IDs son UUID. Timestamps persistidos son `TIMESTAMPTZ`. Foreign keys declaran
`ON DELETE`; recursos históricos se desactivan o revocan y no usan soft delete
genérico. `version_id` aplica optimistic locking a recursos editables.

`Capability` sólo conserva identidad y versión funcional. No contiene provider,
un campo agregado `support` ni dimensiones definitivas de manifest.
