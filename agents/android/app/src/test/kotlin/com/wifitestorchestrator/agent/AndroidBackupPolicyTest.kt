package com.wifitestorchestrator.agent

import java.io.File
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.w3c.dom.Document
import org.w3c.dom.Element

class AndroidBackupPolicyTest {
    private val projectDirectory =
        File(requireNotNull(System.getProperty("wto.android.app.projectDir")))
    private val mergedManifests =
        listOf(
            File(requireNotNull(System.getProperty("wto.android.app.mergedDebugManifest"))),
            File(requireNotNull(System.getProperty("wto.android.app.mergedReleaseManifest"))),
        )

    @Test
    fun `source manifest keeps backup disabled and references both exclusion policies`() {
        val application =
            parse(File(projectDirectory, "src/main/AndroidManifest.xml"))
                .getElementsByTagName("application")
                .item(0) as Element

        assertEquals("false", application.androidAttribute("allowBackup"))
        assertEquals("@xml/backup_rules", application.androidAttribute("fullBackupContent"))
        assertEquals("@xml/data_extraction_rules", application.androidAttribute("dataExtractionRules"))
    }

    @Test
    fun `legacy backup rules exclude credential and device protected database domains`() {
        val document = parse(File(projectDirectory, "src/main/res/xml/backup_rules.xml"))

        assertEquals(
            setOf("database" to ".", "device_database" to "."),
            exclusions(document.documentElement),
        )
    }

    @Test
    fun `modern extraction rules exclude cloud and device transfer database domains`() {
        val document = parse(File(projectDirectory, "src/main/res/xml/data_extraction_rules.xml"))
        val cloud = document.getElementsByTagName("cloud-backup").item(0) as Element
        val transfer = document.getElementsByTagName("device-transfer").item(0) as Element
        val expected = setOf("database" to ".", "device_database" to ".")

        assertEquals(expected, exclusions(cloud))
        assertEquals(expected, exclusions(transfer))
    }

    @Test
    fun `merged debug and release manifests preserve policy and add no components or processes`() {
        mergedManifests.forEach { manifest ->
            val document = parse(manifest)
            val application = document.getElementsByTagName("application").item(0) as Element

            assertEquals("false", application.androidAttribute("allowBackup"))
            assertEquals("false", application.androidAttribute("usesCleartextTraffic"))
            assertEquals("@xml/backup_rules", application.androidAttribute("fullBackupContent"))
            assertEquals("@xml/data_extraction_rules", application.androidAttribute("dataExtractionRules"))
            listOf("activity", "service", "receiver", "provider").forEach { component ->
                assertEquals(0, document.getElementsByTagName(component).length)
            }
            val allNodes = document.getElementsByTagName("*")
            for (index in 0 until allNodes.length) {
                val element = allNodes.item(index) as Element
                assertFalse(element.hasAttributeNS(ANDROID_NAMESPACE, "process"))
            }
        }
    }

    @Test
    fun `merged manifest contains only the existing Internet permission`() {
        mergedManifests.forEach { manifest ->
            val document = parse(manifest)
            val permissions = document.getElementsByTagName("uses-permission")
            val names =
                (0 until permissions.length).map { index ->
                    (permissions.item(index) as Element).androidAttribute("name")
                }.toSet()

            assertEquals(setOf("android.permission.INTERNET"), names)
        }
    }

    private fun parse(file: File): Document {
        assertTrue(file.isFile)
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
        factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "")
        return assertNotNull(factory.newDocumentBuilder().parse(file))
    }

    private fun exclusions(parent: Element): Set<Pair<String, String>> {
        val nodes = parent.getElementsByTagName("exclude")
        return (0 until nodes.length).map { index ->
            val element = nodes.item(index) as Element
            element.getAttribute("domain") to element.getAttribute("path")
        }.toSet()
    }

    private fun Element.androidAttribute(name: String): String =
        getAttributeNS(ANDROID_NAMESPACE, name)

    private companion object {
        const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
    }
}
