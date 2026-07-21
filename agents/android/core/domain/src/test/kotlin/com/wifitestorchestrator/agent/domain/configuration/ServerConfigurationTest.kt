package com.wifitestorchestrator.agent.domain.configuration

import com.wifitestorchestrator.agent.domain.error.ConfigurationIssue
import com.wifitestorchestrator.agent.domain.error.ConfigurationViolation
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidConfiguration
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals

class ServerConfigurationTest {
    @Test
    fun validHttpsUrlProducesTheOnlyServerConfigurationField() {
        val baseUrl = valid("https://example.com")
        val configuration = ServerConfiguration(baseUrl)

        assertEquals("https://example.com/", configuration.baseUrl.toString())
        assertEquals(listOf("baseUrl"), ServerConfiguration::class.java.declaredFields.filterNot { it.isSynthetic }.map { it.name })
    }

    @Test
    fun httpIsRejectedAsInsecure() {
        val error = invalid("http://example.com")

        assertEquals(ConfigurationViolation.INSECURE, error.violation)
        assertEquals(ConfigurationIssue.INSECURE_SCHEME, error.issue)
    }

    @Test
    fun unsupportedSchemesAreRejectedAsSyntax() {
        listOf("ftp://example.com/", "ws://example.com/").forEach {
            val error = invalid(it)
            assertEquals(ConfigurationViolation.SYNTAX, error.violation)
            assertEquals(ConfigurationIssue.UNSUPPORTED_SCHEME, error.issue)
        }
    }

    @Test
    fun relativeAndOpaqueUrisAreRejected() {
        assertEquals(ConfigurationIssue.RELATIVE_URI, invalid("example.com/api").issue)
        assertEquals(ConfigurationIssue.OPAQUE_URI, invalid("https:example.com").issue)
    }

    @Test
    fun missingAuthorityOrHostIsRejected() {
        assertEquals(ConfigurationIssue.MISSING_AUTHORITY, invalid("https:/api").issue)
        assertIs<Invalid>(ServerBaseUrl.parse("https:///api"))
    }

    @Test
    fun userInfoQueryAndFragmentAreRejected() {
        assertEquals(ConfigurationIssue.USER_INFO, invalid("https://user@example.com/").issue)
        assertEquals(ConfigurationIssue.QUERY, invalid("https://example.com/?a=1").issue)
        assertEquals(ConfigurationIssue.FRAGMENT, invalid("https://example.com/#part").issue)
    }

    @Test
    fun asciiAndUnicodeWhitespaceAreRejected() {
        assertEquals(
            ConfigurationIssue.LEADING_OR_TRAILING_WHITESPACE,
            invalid(" https://example.com/").issue,
        )
        assertEquals(ConfigurationIssue.WHITESPACE, invalid("https://exa\u00a0mple.com/").issue)
    }

    @Test
    fun controlCharactersAreRejected() {
        assertEquals(ConfigurationIssue.CONTROL_CHARACTER, invalid("https://example.com/\u0001").issue)
    }

    @Test
    fun hostAndDefaultPortCanonicalizationConverge() {
        val inputs =
            listOf(
                "HTTPS://EXAMPLE.COM",
                "https://example.com:443/",
                "https://example.com/",
            ).map(::valid)

        assertEquals(List(3) { "https://example.com/" }, inputs.map { it.toString() })
        assertEquals(1, inputs.toSet().size)
        assertEquals(1, inputs.map { it.hashCode() }.toSet().size)
    }

    @Test
    fun nonDefaultPortIsPreserved() {
        assertEquals("https://example.com:8443/", valid("https://EXAMPLE.com:8443").toString())
    }

    @Test
    fun invalidPortsAreRejected() {
        listOf(
            "https://example.com:0/",
            "https://example.com:65536/",
            "https://example.com:/",
            "https://example.com:-1/",
        ).forEach { assertIs<Invalid>(ServerBaseUrl.parse(it)) }
    }

    @Test
    fun emptyAndSlashPathsCanonicalizeToRoot() {
        assertEquals("https://example.com/", valid("https://example.com").toString())
        assertEquals("https://example.com/", valid("https://example.com/").toString())
    }

    @Test
    fun basePathIsDirectoryCanonicalAndPreservesCase() {
        assertEquals(
            "https://example.com/API/v1/",
            valid("https://example.com/API/v1").toString(),
        )
        assertEquals(
            valid("https://example.com/API/v1"),
            valid("https://example.com/API/v1/"),
        )
        assertNotEquals(valid("https://example.com/API/"), valid("https://example.com/api/"))
    }

    @Test
    fun dotSegmentsAndDoubleSlashesAreRejected() {
        listOf("/./", "/../", "/api/./v1", "/api/../v1").forEach {
            assertEquals(ConfigurationIssue.DOT_SEGMENT, invalid("https://example.com$it").issue)
        }
        assertEquals(
            ConfigurationIssue.DOUBLE_SLASH_PATH,
            invalid("https://example.com/api//v1").issue,
        )
    }

    @Test
    fun backslashesAndPercentEscapesAreRejectedWithoutDecoding() {
        assertEquals(ConfigurationIssue.BACKSLASH, invalid("https://example.com/api\\v1").issue)
        assertEquals(
            ConfigurationIssue.PERCENT_ENCODING,
            invalid("https://example.com/api%2Fv1").issue,
        )
    }

    @Test
    fun invalidPathCharactersAreRejected() {
        listOf("https://example.com/api:v1", "https://example.com/café").forEach {
            assertEquals(ConfigurationIssue.INVALID_PATH_SEGMENT, invalid(it).issue)
        }
        assertEquals("https://example.com/.well-known/a_b~c-/", valid("https://example.com/.well-known/a_b~c-").toString())
    }

    @Test
    fun unicodeIdnAndPunycodeConverge() {
        val unicode = valid("https://bücher.example/api")
        val ascii = valid("https://xn--bcher-kva.example/api/")

        assertEquals("https://xn--bcher-kva.example/api/", unicode.toString())
        assertEquals(unicode, ascii)
    }

    @Test
    fun idna2003DeviationCharactersAreRejectedFailClosed() {
        listOf(
            "https://fa\u00DF.de",
            "https://\u03C2igma.example",
            "https://join\u200Cer.example",
            "https://join\u200Der.example",
        ).forEach {
            assertEquals(ConfigurationIssue.INVALID_HOST, invalid(it).issue)
        }
    }

    @Test
    fun explicitAsciiPunycodeForDeviationDomainRemainsValid() {
        assertEquals("https://xn--fa-hia.de/", valid("https://xn--fa-hia.de").toString())
    }

    @Test
    fun trailingDotAndUnderscoreHostsAreRejected() {
        assertEquals(ConfigurationIssue.TRAILING_DOT, invalid("https://example.com./").issue)
        assertEquals(ConfigurationIssue.INVALID_HOST, invalid("https://bad_host.example/").issue)
    }

    @Test
    fun ipv4LiteralIsValidatedAndCanonical() {
        listOf("127.0.0.1", "192.168.1.10", "0.0.0.0", "255.255.255.255").forEach {
            assertEquals("https://$it/", valid("https://$it").toString())
        }
        listOf("256.1.1.1", "1.2.3", "1.2.3.4.5", "1..2.3").forEach {
            assertEquals(ConfigurationIssue.INVALID_IPV4, invalid("https://$it/").issue)
        }
    }

    @Test
    fun ambiguousIpv4LeadingZerosAreRejected() {
        listOf("192.168.001.10", "192.168.001.010").forEach {
            assertEquals(ConfigurationIssue.AMBIGUOUS_IPV4, invalid("https://$it/").issue)
        }
    }

    @Test
    fun hexadecimalIpv4FormsCannotFallBackToDns() {
        listOf(
            "0x7f.0.0.1",
            "127.0.0x0.1",
            "127.0x0.0.1",
            "0x7f000001",
            "0x7f.0x0.0x0.0x1",
            "0X7F.0.0.1",
            "0x7f.0.0.01",
        ).forEach {
            assertEquals(ConfigurationIssue.AMBIGUOUS_IPV4, invalid("https://$it/").issue)
        }
    }

    @Test
    fun octalAndAbbreviatedIpv4FormsAreRejected() {
        listOf("0177.0.0.1", "0300.0250.0001.0012").forEach {
            assertEquals(ConfigurationIssue.AMBIGUOUS_IPV4, invalid("https://$it/").issue)
        }
        listOf("127.1", "127.0.1").forEach {
            assertEquals(ConfigurationIssue.INVALID_IPV4, invalid("https://$it/").issue)
        }
    }

    @Test
    fun decimalIntegerHostsCannotFallBackToDns() {
        listOf("1", "127", "2130706433", "4294967295").forEach {
            assertEquals(ConfigurationIssue.INVALID_IPV4, invalid("https://$it/").issue)
        }
    }

    @Test
    fun idnNormalizationCannotObfuscateNumericHosts() {
        listOf(
            "\uFF11\uFF12\uFF17.\uFF10.\uFF10.\uFF11",
            "\uFF11\uFF19\uFF12.\uFF11\uFF16\uFF18.\uFF10\uFF10\uFF11.\uFF10\uFF11\uFF10",
            "\u0661\u0662\u0667.\u0660.\u0660.\u0661",
            "\uFF10\uFF58\uFF17\uFF46.\uFF10.\uFF10.\uFF11",
            "\uFF10\uFF38\uFF17\uFF26\uFF10\uFF10\uFF10\uFF10\uFF10\uFF11",
        ).forEach {
            assertEquals(ConfigurationIssue.AMBIGUOUS_IPV4, invalid("https://$it/").issue)
        }
    }

    @Test
    fun alphanumericDnsHostsRemainValid() {
        listOf("1example.com", "deadbeef.example", "cafe.example", "abc123.example").forEach {
            assertEquals("https://$it/", valid("https://$it/").toString())
        }
    }

    @Test
    fun bracketedIpv6IsValidatedAndCanonicalized() {
        assertEquals(
            "https://[2001:db8::1]/",
            valid("https://[2001:0DB8:0:0:0:0:0:1]:443").toString(),
        )
        assertEquals("https://[::ffff:c000:201]/", valid("https://[::ffff:192.0.2.1]").toString())
    }

    @Test
    fun unbracketedInvalidAndScopedIpv6AreRejected() {
        assertIs<Invalid>(ServerBaseUrl.parse("https://2001:db8::1/"))
        assertIs<Invalid>(ServerBaseUrl.parse("https://[2001:db8:::1]/"))
        assertEquals(ConfigurationIssue.IPV6_SCOPE, invalid("https://[fe80::1%25eth0]/").issue)
    }

    @Test
    fun localhostIsAllowedWithoutReachabilityChecks() {
        assertEquals("https://localhost/", valid("https://LOCALHOST").toString())
    }

    private fun valid(raw: String): ServerBaseUrl =
        assertIs<Valid<ServerBaseUrl>>(ServerBaseUrl.parse(raw)).value

    private fun invalid(raw: String): InvalidConfiguration =
        assertIs<InvalidConfiguration>(assertIs<Invalid>(ServerBaseUrl.parse(raw)).error)
}
