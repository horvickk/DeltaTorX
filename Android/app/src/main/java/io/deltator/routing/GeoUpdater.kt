package io.deltator.routing

import android.content.Context
import io.deltator.Config
import io.deltator.util.AppLog as Log
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * "Update rules": fetch the current runetfreedom geosite.dat / geoip.dat and keep
 * only the lists this device can use.
 *
 * The full files are large (about 70 MB and 18 MB), so they are never stored:
 * the download is read as a stream and only the wanted entries are written out,
 * in the same format the bundled copies use. What is wanted is every list the
 * presets of every country refer to plus every list the user's own rules name,
 * so switching country after an update does not need another one.
 */
object GeoUpdater {
    private const val TAG = "GeoUpdater"

    private const val BASE = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/"
    private const val MIRROR = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/"

    /** Codes always kept, whatever the rules say. */
    private val ALWAYS_SITE = setOf("category-ads-all", "private")
    private val ALWAYS_IP = setOf("private")

    data class Result(val ok: Boolean, val message: String)

    fun update(context: Context, rules: List<RouteRule>, onProgress: (String) -> Unit): Result {
        val sites = HashSet(ALWAYS_SITE)
        val ips = HashSet(ALWAYS_IP)
        val all = rules + RoutePresets.COUNTRIES.flatMap { RoutePresets.defaults(it.code) }
        for (r in all) {
            r.domains.forEach { d ->
                if (d.startsWith("geosite:", true)) sites += d.substring(8).substringBefore('@').trim().lowercase()
            }
            r.ips.forEach { i ->
                if (i.startsWith("geoip:", true)) ips += i.substring(6).trim().lowercase()
            }
        }
        val dir = GeoData.dir(context)
        val siteResult = fetch(GeoData.GEOSITE_FILE, sites, File(dir, GeoData.GEOSITE_FILE), onProgress)
        val ipResult = fetch(GeoData.GEOIP_FILE, ips, File(dir, GeoData.GEOIP_FILE), onProgress)
        if (siteResult == null && ipResult == null) {
            return Result(false, "Download failed. Check the connection and try again.")
        }
        if (siteResult != null || ipResult != null) {
            Config.routesUpdatedAt = System.currentTimeMillis()
        }
        val parts = listOfNotNull(
            siteResult?.let { "${it} site lists" } ?: "site lists failed",
            ipResult?.let { "${it} IP lists" } ?: "IP lists failed"
        )
        return Result(siteResult != null && ipResult != null, "Updated: " + parts.joinToString(", "))
    }

    /**
     * Stream [name] and keep the [wanted] entries in [target]. Direct first,
     * then the mirror, then the same two through Tor when it is running, since
     * GitHub itself may be what the network blocks. Returns the number of
     * entries kept, or null when every route failed.
     */
    private fun fetch(name: String, wanted: Set<String>, target: File, onProgress: (String) -> Unit): Int? {
        val routes = buildList {
            add(BASE + name to Proxy.NO_PROXY)
            add(MIRROR + name to Proxy.NO_PROXY)
            if (io.deltator.tunnel.TorSocksBridge.isRunning()) {
                val tor = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", Config.proxyPort))
                add(BASE + name to tor)
                add(MIRROR + name to tor)
            }
        }
        for ((url, proxy) in routes) {
            val via = if (proxy == Proxy.NO_PROXY) "direct" else "via Tor"
            onProgress("Downloading $name ($via) …")
            try {
                val tmp = File(target.path + ".tmp")
                var kept = 0
                open(url, proxy).use { input ->
                    val counting = CountingStream(input) { read ->
                        onProgress("Downloading $name ($via) · ${read / (1024 * 1024)} MB")
                    }
                    tmp.outputStream().buffered(1 shl 16).use { out ->
                        GeoData.forEachEntry(counting, wanted) { _, codeBytes, rest ->
                            GeoData.writeEntry(out, codeBytes, rest)
                            kept++
                        }
                    }
                }
                if (kept == 0) {
                    tmp.delete()
                    Log.w(TAG, "$name from $url ($via) held none of the wanted lists")
                    continue
                }
                if (!tmp.renameTo(target)) { tmp.copyTo(target, true); tmp.delete() }
                Log.i(TAG, "$name updated from $url ($via): $kept list(s)")
                return kept
            } catch (e: Exception) {
                Log.w(TAG, "$name from $url ($via) failed: ${e.message}")
            }
        }
        return null
    }

    private fun open(url: String, proxy: Proxy): InputStream {
        var current = URL(url)
        repeat(5) {
            val conn = current.openConnection(proxy) as HttpURLConnection
            conn.connectTimeout = 20_000
            conn.readTimeout = 30_000
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "DeltaTor")
            when (val code = conn.responseCode) {
                HttpURLConnection.HTTP_OK -> return conn.inputStream
                in 301..308 -> {
                    val next = conn.getHeaderField("Location") ?: throw java.io.IOException("redirect without Location")
                    conn.disconnect()
                    current = URL(current, next)
                }
                else -> { conn.disconnect(); throw java.io.IOException("HTTP $code") }
            }
        }
        throw java.io.IOException("too many redirects")
    }

    /** Reports progress about once per megabyte. */
    private class CountingStream(
        private val inner: InputStream,
        private val onMegabyte: (Long) -> Unit
    ) : InputStream() {
        private var total = 0L
        private var nextReport = 1L shl 20

        private fun count(n: Int) {
            if (n <= 0) return
            total += n
            if (total >= nextReport) { nextReport = total + (1L shl 20); onMegabyte(total) }
        }

        override fun read(): Int = inner.read().also { if (it >= 0) count(1) }
        override fun read(b: ByteArray, off: Int, len: Int): Int = inner.read(b, off, len).also { count(it) }
        override fun skip(n: Long): Long = inner.skip(n).also { count(it.toInt()) }
        override fun available(): Int = inner.available()
        override fun close() = inner.close()
    }
}
