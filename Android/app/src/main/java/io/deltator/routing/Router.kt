package io.deltator.routing

import android.content.Context
import io.deltator.util.AppLog as Log
import java.net.IDN

/**
 * The compiled form of the route list: what the SOCKS bridge asks, once per
 * connection, where that connection goes.
 *
 * Rules are tried top to bottom and the first match wins, as in NekoBox; nothing
 * matching means Tor. All lookups are hash sets and binary searches, so a
 * decision costs microseconds no matter how long the lists are.
 */
class Router private constructor(private val rules: List<Compiled>) {

    val enabled: Boolean get() = rules.isNotEmpty()

    /** Some rule looks at the domain: an IP-only connection has to be sniffed. */
    val wantsDomain: Boolean = rules.any { it.domain != null }

    /** Some rule looks at the protocol: every connection has to be sniffed. */
    val wantsProtocol: Boolean = rules.any { it.protocols != null }

    /**
     * Where a connection goes.
     *
     * [host] is the domain when one is known (asked for by name or sniffed),
     * [ip] the literal destination address when one is known.
     */
    fun decide(host: String?, ip: ByteArray?, port: Int, protocol: String?): RouteOutbound {
        val h = host?.let(::normalizeHost)
        for (r in rules) {
            if (r.matches(h, ip, port, protocol)) return r.outbound
        }
        return RouteOutbound.PROXY
    }

    /**
     * The verdict for a DNS name alone, from rules that look at nothing but the
     * domain. Lets blocked names fail at the lookup and lets bypassed names be
     * resolved by the local network, so they get the addresses a domestic user
     * would get rather than the ones a Tor exit abroad sees.
     *
     * Rules without a domain condition are skipped: only the lookup is decided
     * here, and the connection that follows still goes through [decide]. A
     * matching rule that also needs an IP, port or protocol cannot be settled
     * from the name, so it ends the search with null.
     */
    fun decideName(name: String): RouteOutbound? {
        val h = normalizeHost(name)
        for (r in rules) {
            val domain = r.domain ?: continue
            if (!domain.matches(h)) continue
            if (r.ips != null || r.protocols != null || r.ports != null) return null
            return r.outbound
        }
        return null
    }

    private class Compiled(
        val outbound: RouteOutbound,
        val domain: DomainMatcher?,
        val ips: IpSet?,
        val protocols: Set<String>?,
        val ports: IntArray?
    ) {
        fun matches(host: String?, ip: ByteArray?, port: Int, protocol: String?): Boolean {
            if (domain != null && (host == null || !domain.matches(host))) return false
            if (ips != null && (ip == null || !ips.contains(ip))) return false
            if (protocols != null && (protocol == null || protocol !in protocols)) return false
            if (ports != null && !portMatches(ports, port)) return false
            return true
        }
    }

    companion object {
        private const val TAG = "Router"

        val DISABLED = Router(emptyList())

        fun normalizeHost(host: String): String {
            val h = host.trim().trimEnd('.').lowercase()
            if (h.all { it.code < 0x80 }) return h
            return try { IDN.toASCII(h, IDN.ALLOW_UNASSIGNED).lowercase() } catch (_: Exception) { h }
        }

        /**
         * Compile the enabled rules. Reads geosite/geoip data, so call it off the
         * main thread. Rules whose every list failed to load still compile, as
         * rules that never match, rather than as rules that match everything.
         */
        fun compile(context: Context, list: List<RouteRule>): Router {
            val active = list.filter { it.enabled && !it.isEmpty }
            if (active.isEmpty()) return DISABLED
            val started = System.currentTimeMillis()

            val siteSpecs = HashSet<String>()
            val ipCodes = HashSet<String>()
            for (r in active) {
                r.domains.forEach { d -> prefixed(d, "geosite:")?.let { siteSpecs += it.lowercase() } }
                r.ips.forEach { i -> prefixed(i, "geoip:")?.let { ipCodes += it.lowercase() } }
            }
            val sites = GeoData.loadGeosite(context, siteSpecs)
            val geoips = GeoData.loadGeoip(context, ipCodes)

            val compiled = active.map { r ->
                Compiled(
                    outbound = r.outbound,
                    domain = if (r.domains.isEmpty()) null else DomainMatcher.Builder().apply {
                        for (d in r.domains) {
                            val site = prefixed(d, "geosite:")
                            if (site != null) sites[site.lowercase()]?.forEach { add(it.type, it.value) }
                            else addText(d)
                        }
                    }.build(),
                    ips = if (r.ips.isEmpty()) null else IpSet.Builder().apply {
                        for (i in r.ips) {
                            val code = prefixed(i, "geoip:")
                            if (code != null) geoips[code.lowercase()]?.let { addAll(it) }
                            else if (!addText(i)) Log.w(TAG, "${r.name}: bad IP entry '$i'")
                        }
                    }.build(),
                    protocols = r.protocols.map { it.lowercase() }.toSet().ifEmpty { null },
                    ports = parsePorts(r.ports)
                )
            }
            Log.i(TAG, "compiled ${compiled.size} rule(s) in ${System.currentTimeMillis() - started} ms")
            return Router(compiled)
        }

        private fun prefixed(entry: String, prefix: String): String? =
            if (entry.startsWith(prefix, ignoreCase = true)) entry.substring(prefix.length).trim() else null

        /** "80,443,1000-2000" as flat [from, to] pairs; null when blank or invalid. */
        fun parsePorts(text: String): IntArray? {
            if (text.isBlank()) return null
            val out = ArrayList<Int>()
            for (part in text.split(',', ' ', ';')) {
                val p = part.trim()
                if (p.isEmpty()) continue
                val dash = p.indexOf('-')
                val from = (if (dash < 0) p else p.substring(0, dash)).toIntOrNull() ?: continue
                val to = (if (dash < 0) p else p.substring(dash + 1)).toIntOrNull() ?: continue
                if (from in 0..65535 && to in from..65535) { out += from; out += to }
            }
            return if (out.isEmpty()) null else out.toIntArray()
        }

        private fun portMatches(ranges: IntArray, port: Int): Boolean {
            var i = 0
            while (i < ranges.size) {
                if (port >= ranges[i] && port <= ranges[i + 1]) return true
                i += 2
            }
            return false
        }
    }
}

/** Domain lookups in v2ray semantics: full, suffix, keyword and regexp entries. */
class DomainMatcher private constructor(
    private val full: HashSet<String>,
    private val suffix: HashSet<String>,
    private val keywords: Array<String>,
    private val regex: Regex?
) {
    fun matches(host: String): Boolean {
        if (host.isEmpty()) return false
        if (host in full || host in suffix) return true
        if (suffix.isNotEmpty()) {
            var dot = host.indexOf('.')
            while (dot >= 0) {
                if (host.substring(dot + 1) in suffix) return true
                dot = host.indexOf('.', dot + 1)
            }
        }
        for (k in keywords) if (host.contains(k)) return true
        return regex?.containsMatchIn(host) == true
    }

    class Builder {
        private val full = HashSet<String>()
        private val suffix = HashSet<String>()
        private val keywords = LinkedHashSet<String>()
        private val regexes = LinkedHashSet<String>()

        fun add(type: Int, value: String) {
            val v = value.trim().lowercase()
            if (v.isEmpty()) return
            when (type) {
                GeoData.TYPE_FULL -> full += Router.normalizeHost(v)
                GeoData.TYPE_DOMAIN -> suffix += Router.normalizeHost(v.trimStart('.'))
                GeoData.TYPE_KEYWORD -> keywords += v
                GeoData.TYPE_REGEX -> regexes += value.trim()
            }
        }

        /** A typed entry: `domain:`, `full:`, `keyword:`, `regexp:` or a bare name. */
        fun addText(entry: String) {
            val e = entry.trim()
            val colon = e.indexOf(':')
            val kind = if (colon > 0) e.substring(0, colon).lowercase() else ""
            val value = if (colon > 0) e.substring(colon + 1) else e
            when (kind) {
                "full" -> add(GeoData.TYPE_FULL, value)
                "domain" -> add(GeoData.TYPE_DOMAIN, value)
                "keyword" -> add(GeoData.TYPE_KEYWORD, value)
                "regexp" -> add(GeoData.TYPE_REGEX, value)
                else -> add(GeoData.TYPE_DOMAIN, e)
            }
        }

        fun build(): DomainMatcher {
            // One alternation is much cheaper than a loop over separate patterns,
            // and a pattern that does not compile is dropped instead of taking
            // the whole rule down with it.
            val valid = regexes.filter { runCatching { Regex(it) }.isSuccess }
            val regex = if (valid.isEmpty()) null else
                Regex(valid.joinToString("|") { "(?:$it)" }, RegexOption.IGNORE_CASE)
            return DomainMatcher(full, suffix, keywords.toTypedArray(), regex)
        }
    }
}
