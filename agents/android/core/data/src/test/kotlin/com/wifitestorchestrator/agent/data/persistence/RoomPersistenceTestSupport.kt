package com.wifitestorchestrator.agent.data.persistence

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Before

internal const val FIRST_INSTALLATION_ID = "11111111-1111-4111-8111-111111111111"
internal const val SECOND_INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
internal const val FIRST_SERVER_URL = "https://lab.example/"
internal const val SECOND_SERVER_URL = "https://backup.example/Tenant/"

internal fun localIdentity(raw: String = FIRST_INSTALLATION_ID): LocalInstallationIdentity {
    val parsed = InstallationId.parse(raw)
    check(parsed is Valid)
    return LocalInstallationIdentity(parsed.value)
}

internal fun serverConfiguration(raw: String = FIRST_SERVER_URL): ServerConfiguration {
    val parsed = ServerBaseUrl.parse(raw)
    check(parsed is Valid)
    return ServerConfiguration(parsed.value)
}

internal abstract class RoomPersistenceTestBase {
    protected lateinit var context: Context

    private val databases = mutableListOf<WtoAgentDatabase>()
    private val databaseNames = mutableSetOf<String>()

    @Before
    fun configureRoomTestContext() {
        context = ApplicationProvider.getApplicationContext()
    }

    @After
    fun closeRoomTestDatabases() {
        databases.asReversed().forEach { database ->
            try {
                database.close()
            } catch (_: Exception) {
                // Tests still remove only their own generated database files.
            }
        }
        databaseNames.forEach(::removeTestDatabaseFiles)
        databases.clear()
        databaseNames.clear()
    }

    protected fun newDatabaseName(@Suppress("UNUSED_PARAMETER") prefix: String): String =
        "r${databaseSequence.incrementAndGet()}.db"

    protected fun openDatabase(name: String = newDatabaseName("wto-room-test")): WtoAgentDatabase {
        databaseNames += name
        return WtoAgentDatabase.build(context, name).also(databases::add)
    }

    protected fun reopenDatabase(name: String): WtoAgentDatabase =
        WtoAgentDatabase.build(context, name).also(databases::add)

    protected fun repository(database: WtoAgentDatabase): LocalStateRepository =
        RoomLocalStateRepository(WtoAgentDatabaseProvider { database })

    protected fun databaseFile(name: String): File = File(context.noBackupFilesDir, name)

    protected fun removeTestDatabaseFiles(name: String) {
        listOf(name, "$name-wal", "$name-shm", "$name-journal").forEach { fileName ->
            try {
                File(context.noBackupFilesDir, fileName).delete()
            } catch (_: SecurityException) {
                // Test cleanup must not hide the preceding assertion result.
            }
        }
    }

    private companion object {
        val databaseSequence = AtomicInteger()
    }
}
