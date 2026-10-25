package io.deltator.routing

import io.deltator.tunnel.ProtocolSniffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream

class RouterTest {

    private fun ip(s: String) = GeoData.parseIp(s)!!

    @Test fun parsesIpLiterals() {
        assertEquals(4, GeoData.parseIp("1.2.3.4")!!.size)
        assertEquals(16, GeoData.parseIp("2a00:1450::1")!!.size)
        assertNull(GeoData.parseIp("example.com"))
        assertNull(GeoData.parseIp("1.2.3.256"))
        assertNull(GeoData.parseIp("1.2.3"))
    }

    @Test fun ipSetMergesNestedRanges() {
        // A wide range with a narrower one inside it: the old "last start <= ip"
        // search answered no for addresses after the inner range.
        val set = IpSet.Builder().apply {
            addText("10.0.0.0/8")
            addText("10.1.0.0/16")
            addText("2001:db8::/32")
        }.build()
        assertTrue(set.contains(ip("10.200.0.1")))
        assertTrue(set.contains(ip("10.1.2.3")))
        assertFalse(set.contains(ip("11.0.0.1")))
        assertTrue(set.contains(ip("2001:db8:ffff::1")))
        assertFalse(set.contains(ip("2001:db9::1")))
        assertTrue(set.contains(ip("::ffff:10.9.9.9")))
        assertEquals(1, set.v4Count)
    }

    @Test fun privateRanges() {
        assertTrue(IpSet.PRIVATE.contains(ip("192.168.1.1")))
        assertTrue(IpSet.PRIVATE.contains(ip("fe80::1")))
        assertFalse(IpSet.PRIVATE.contains(ip("8.8.8.8")))
    }

    @Test fun domainMatcherSemantics() {
        val m = DomainMatcher.Builder().apply {
            addText("domain:ru")
            addText("full:exact.com")
            addText("keyword:tracker")
            addText("regexp:^ads[0-9]+\\.")
            addText("example.org")
        }.build()
        assertTrue(m.matches("yandex.ru"))
        assertTrue(m.matches("ru"))
        assertFalse(m.matches("guru"))
        assertTrue(m.matches("exact.com"))
        assertFalse(m.matches("www.exact.com"))
        assertTrue(m.matches("my-tracker.net"))
        assertTrue(m.matches("ads12.foo.com"))
        assertTrue(m.matches("a.b.example.org"))
        assertFalse(m.matches("example.com"))
    }

    @Test fun firstMatchWinsAndFieldsCombine() {
        val rules = listOf(
            RouteRule(1, "bt", protocols = listOf("bittorrent"), outbound = RouteOutbound.BYPASS),
            RouteRule(2, "block", domains = listOf("domain:ads.example"), outbound = RouteOutbound.BLOCK),
            RouteRule(3, "ru", domains = listOf("domain:ru", "domain:xn--p1ai"), outbound = RouteOutbound.BYPASS),
            RouteRule(4, "ru ip", ips = listOf("5.0.0.0/8"), ports = "443", outbound = RouteOutbound.BYPASS),
            RouteRule(5, "off", enabled = false, ips = listOf("0.0.0.0/0"), outbound = RouteOutbound.BLOCK)
        )
        val r = Router.compile(rules, { emptyMap() }, { emptyMap() })
        assertTrue(r.wantsDomain && r.wantsProtocol)
        assertEquals(RouteOutbound.BYPASS, r.decide(null, ip("1.1.1.1"), 6881, "bittorrent"))
        assertEquals(RouteOutbound.BLOCK, r.decide("x.ads.example", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, r.decide("Mail.RU.", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, r.decide("пример.рф", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, r.decide(null, ip("5.1.2.3"), 443, null))
        assertEquals(RouteOutbound.PROXY, r.decide(null, ip("5.1.2.3"), 80, null))
        assertEquals(RouteOutbound.PROXY, r.decide("google.com", ip("8.8.8.8"), 443, "tls"))
        assertEquals(RouteOutbound.BLOCK, r.decideName("ads.example"))
        assertEquals(RouteOutbound.BYPASS, r.decideName("vk.ru"))
        assertNull(r.decideName("google.com"))
    }

    @Test fun parsesPorts() {
        assertNull(Router.parsePorts(""))
        assertEquals(listOf(80, 80, 1000, 2000), Router.parsePorts("80, 1000-2000, bad, 70000")!!.toList())
    }

    @Test fun sniffsSplitClientHello() {
        val hello = clientHello("www.example.ru")
        // Delivered in two pieces, the way a large ClientHello arrives.
        val stream = object : InputStream() {
            val parts = ArrayDeque(listOf(hello.copyOfRange(0, 100), hello.copyOfRange(100, hello.size)))
            var cur = ByteArrayInputStream(ByteArray(0))
            override fun read(): Int = throw UnsupportedOperationException()
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (cur.available() == 0) cur = ByteArrayInputStream(parts.removeFirstOrNull() ?: return -1)
                return cur.read(b, off, len)
            }
        }
        val res = ProtocolSniffer.sniff(stream)
        assertEquals("www.example.ru", res.domain)
        assertEquals(ProtocolSniffer.PROTO_TLS, res.protocol)
        assertEquals(hello.size, res.bufferedLength)
    }

    @Test fun sniffsHttpAndBitTorrent() {
        val http = ProtocolSniffer.sniff(ByteArrayInputStream("GET / HTTP/1.1\r\nHost: Site.RU:8080\r\n\r\n".toByteArray()))
        assertEquals("site.ru", http.domain)
        assertEquals(ProtocolSniffer.PROTO_HTTP, http.protocol)
        val bt = ProtocolSniffer.sniff(ByteArrayInputStream("\u0013BitTorrent protocol".toByteArray() + ByteArray(48)))
        assertEquals(ProtocolSniffer.PROTO_BITTORRENT, bt.protocol)
    }

    @Test fun datWriteAndReadRoundTrip() {
        // One geosite entry with a domain-type value, written by writeEntry.
        val domain = byteArrayOf(0x08, 0x02, 0x12, 0x02) + "ru".toByteArray()
        val rest = byteArrayOf(0x12, domain.size.toByte()) + domain
        val out = ByteArrayOutputStream()
        GeoData.writeEntry(out, "OTHER".toByteArray(), byteArrayOf())
        GeoData.writeEntry(out, "TEST".toByteArray(), rest)
        val bytes = out.toByteArray()
        val sites = GeoData.loadGeosite(listOf({ ByteArrayInputStream(bytes) }), setOf("test"))
        assertEquals(1, sites["test"]!!.size)
        assertEquals("ru", sites["test"]!![0].value)
    }

    /** The bundled lists produced by the fetchGeoLists build task, when present. */
    @Test fun bundledListsCoverRussia() {
        val dir = File("build/generated/geoAssets/geo")
        assumeTrue(File(dir, "geosite.dat").isFile && File(dir, "geoip.dat").isFile)
        val t0 = System.currentTimeMillis()
        val router = Router.compile(
            RoutePresets.defaults("ru"),
            { GeoData.loadGeosite(listOf({ File(dir, "geosite.dat").inputStream() }), it) },
            { GeoData.loadGeoip(listOf({ File(dir, "geoip.dat").inputStream() }), it) }
        )
        println("compiled RU defaults in ${System.currentTimeMillis() - t0} ms")
        assertEquals(RouteOutbound.BYPASS, router.decide("www.gosuslugi.ru", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, router.decide("ya.ru", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, router.decide("music.yandex.com", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, router.decide("xn--80adxhks.xn--80adxhks", null, 443, "tls"))
        assertEquals(RouteOutbound.BYPASS, router.decide(null, ip("77.88.8.8"), 53, null))   // Yandex DNS
        assertEquals(RouteOutbound.BLOCK, router.decide("doubleclick.net", null, 443, "tls"))
        assertEquals(RouteOutbound.PROXY, router.decide("www.torproject.org", ip("116.202.120.166"), 443, "tls"))

        val sites = GeoData.loadGeosite(
            listOf({ File(dir, "geosite.dat").inputStream() }),
            setOf("category-ru", "category-gov-ru", "category-ads-all", "ru-available-only-inside")
        )
        assertEquals(4, sites.size)
        assertTrue(sites.getValue("category-ads-all").size > 1000)
        val ips = GeoData.loadGeoip(listOf({ File(dir, "geoip.dat").inputStream() }), setOf("ru"))
        assertNotNull(ips["ru"])
        assertTrue(ips.getValue("ru").v4Count > 1000)
    }

    private fun clientHello(sni: String): ByteArray {
        val name = sni.toByteArray()
        val sniExt = ByteArrayOutputStream().apply {
            write16(name.size + 3); write(0); write16(name.size); write(name)
        }.toByteArray()
        val ext = ByteArrayOutputStream().apply {
            // padding extension first, to push the SNI past the first segment
            write16(0x0015); write16(300); write(ByteArray(300))
            write16(0x0000); write16(sniExt.size); write(sniExt)
        }.toByteArray()
        val body = ByteArrayOutputStream().apply {
            write16(0x0303); write(ByteArray(32)); write(0)
            write16(2); write16(0x1301); write(1); write(0)
            write16(ext.size); write(ext)
        }.toByteArray()
        val hs = byteArrayOf(0x01, 0, (body.size shr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(0x16, 0x03, 0x01, (hs.size shr 8).toByte(), hs.size.toByte()) + hs
    }

    private fun ByteArrayOutputStream.write16(v: Int) { write(v shr 8); write(v and 0xFF) }
}
