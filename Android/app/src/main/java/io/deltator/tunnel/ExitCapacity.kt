package io.deltator.tunnel

import android.content.Context
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

/**
 * How much exit capacity a country has.
 *
 * @param exits how many relays in that country carried the Exit flag
 * @param weight that country's share of Tor exit traffic (exit probability), 0..1
 */
data class ExitCapacity(val exits: Int, val weight: Float)

/**
 * Per-country exit capacity, read from the bundled table.
 *
 * The country picker used to be every country in the bundled GeoIP file: 248 of
 * them, of which 187 have no Tor exit at all and never did. Picking one of those
 * was not a slow choice, it was a choice that could not work, and nothing on
 * screen said so. On top of that sat a hand-written order of 24 countries whose
 * own comment claimed it was derived from recorded exits; checked against the
 * relay database, 12 of the 24 were dead or carried a rounding error's worth of
 * bandwidth, and two of them had no exits at all.
 *
 * The table answers the question instead, from Tor's own relay database: which
 * countries have exits running right now, how many, and what share of all exit
 * traffic they carry. Share is the figure that predicts speed, because a
 * country can have a hundred slow exits or a few quick ones. The spread is steep
 * enough to be worth having: the top ten countries carry about 95% of it.
 *
 * A copy ships as an asset so the list works offline from the first launch;
 * the app refreshes it from onionoo once a day. The recipe for the bundled copy
 * is in its own header.
 */
object ExitCapacityIndex {
    private const val TAG = "ExitCapacity"
    private const val ASSET = "geoip/exit-capacity.tsv"
    private const val CACHE = "exit-capacity.tsv"
    private const val REFRESH_MS = 24 * 60 * 60 * 1000L
    private const val ONIONOO =
        "https://onionoo.torproject.org/details?search=flag:Exit%20running:true" +
            "&fields=country,country_name,exit_probability"

    private val _byCountry = MutableStateFlow<Map<String, ExitCapacity>>(emptyMap())
    private val started = AtomicBoolean(false)

    /** Country code to capacity. Empty until the table is read. */
    val byCountry: StateFlow<Map<String, ExitCapacity>> = _byCountry.asStateFlow()

    /**
     * Reads the table once, off the main thread, and refreshes it from the Tor
     * relay database when the cached copy is a day old. Never blocks the caller.
     */
    fun load(context: Context) {
        if (!started.compareAndSet(false, true)) return
        val app = context.applicationContext
        Thread({
            val cache = File(app.filesDir, CACHE)
            val table = (if (cache.isFile) parse(cache.readLines()) else emptyMap())
                .ifEmpty { readAsset(app) }
            if (table.isNotEmpty()) _byCountry.value = table
            Log.i(TAG, "exit capacity: ${table.size} countries with running exits")
            if (!cache.isFile || System.currentTimeMillis() - cache.lastModified() > REFRESH_MS) {
                refresh(cache)
            }
        }, "deltator-exit-capacity").apply { isDaemon = true }.start()
    }

    private fun readAsset(context: Context): Map<String, ExitCapacity> = try {
        context.assets.open(ASSET).use { input ->
            parse(BufferedReader(InputStreamReader(input, Charsets.UTF_8)).readLines())
        }
    } catch (e: Exception) {
        Log.w(TAG, "exit capacity table unavailable: ${e.message}")
        emptyMap()
    }

    /**
     * `code, name, exits, share` lines. Shares are normalised to sum to 1, so a
     * table written with a different measure (an older copy summed
     * consensus_weight_fraction, the share of the whole network rather than of
     * its exits, which made every country look three times smaller) still
     * reads as shares of exit traffic.
     */
    private fun parse(lines: List<String>): Map<String, ExitCapacity> {
        val raw = HashMap<String, Pair<Int, Float>>()
        for (line in lines) {
            if (line.isBlank() || line.startsWith("#")) continue
            val p = line.split('\t')
            if (p.size < 4) continue
            val cc = p[0].trim().uppercase()
            val n = p[2].trim().toIntOrNull() ?: continue
            val w = p[3].trim().toFloatOrNull() ?: continue
            if (cc.length != 2 || n <= 0) continue
            raw[cc] = n to w
        }
        val total = raw.values.sumOf { it.second.toDouble() }.toFloat()
        if (total <= 0f) return emptyMap()
        return raw.mapValues { (_, v) -> ExitCapacity(v.first, v.second / total) }
    }

    /**
     * Ask onionoo for the running exits and store them in the table format.
     * Direct first; through Tor when it is up, since the network may block the
     * Tor Project's own sites.
     */
    private fun refresh(cache: File) {
        val routes = buildList {
            add(Proxy.NO_PROXY)
            if (TorSocksBridge.isRunning()) {
                add(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", io.deltator.Config.proxyPort)))
            }
        }
        for (proxy in routes) {
            try {
                val conn = URL(ONIONOO).openConnection(proxy) as HttpURLConnection
                conn.connectTimeout = 20_000
                conn.readTimeout = 30_000
                val text = try {
                    if (conn.responseCode != HttpURLConnection.HTTP_OK) throw java.io.IOException("HTTP ${conn.responseCode}")
                    conn.inputStream.bufferedReader().use { it.readText() }
                } finally {
                    conn.disconnect()
                }
                val relays = JSONObject(text).getJSONArray("relays")
                val exits = HashMap<String, Int>()
                val share = HashMap<String, Double>()
                val names = HashMap<String, String>()
                for (i in 0 until relays.length()) {
                    val r = relays.getJSONObject(i)
                    val cc = r.optString("country").uppercase()
                    if (cc.length != 2) continue
                    exits[cc] = (exits[cc] ?: 0) + 1
                    share[cc] = (share[cc] ?: 0.0) + r.optDouble("exit_probability", 0.0)
                    names[cc] = r.optString("country_name", cc)
                }
                if (exits.isEmpty()) continue
                val lines = share.entries.sortedByDescending { it.value }.map { (cc, w) ->
                    "$cc\t${names[cc]}\t${exits[cc]}\t$w"
                }
                val table = parse(lines)
                if (table.isEmpty()) continue
                val tmp = File(cache.path + ".tmp")
                tmp.writeText(lines.joinToString("\n", postfix = "\n"))
                if (!tmp.renameTo(cache)) { tmp.copyTo(cache, true); tmp.delete() }
                _byCountry.value = table
                Log.i(TAG, "exit capacity refreshed: ${table.size} countries, ${exits.values.sum()} exits")
                return
            } catch (e: Exception) {
                Log.w(TAG, "exit capacity refresh failed: ${e.message}")
            }
        }
    }
}
