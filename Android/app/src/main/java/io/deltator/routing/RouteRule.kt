package io.deltator.routing

import org.json.JSONArray
import org.json.JSONObject

/** Where a connection matched by a [RouteRule] goes. */
enum class RouteOutbound(val value: String, val label: String) {
    /** Through Tor, as if no rule had matched. */
    PROXY("proxy", "Proxy"),
    /** Straight to the internet, outside Tor. */
    BYPASS("bypass", "Bypass"),
    /** Dropped. */
    BLOCK("block", "Block");

    companion object {
        fun fromValue(value: String?): RouteOutbound =
            entries.firstOrNull { it.value == value } ?: PROXY
    }
}

/**
 * One routing rule, in the same shape NekoBox and v2ray use.
 *
 * Inside one field the entries are alternatives (any domain of [domains] matches);
 * across fields they all have to hold (a rule with both [domains] and [ports] wants
 * a matching domain on a matching port). Empty fields are ignored. A rule with
 * every field empty never matches.
 *
 * Domain entries: `geosite:code[@attr]`, `domain:suffix`, `full:host`,
 * `keyword:part`, `regexp:pattern`, or a bare name (treated as `domain:`).
 * IP entries: `geoip:code` (`geoip:private` is built in), or a CIDR / single IP.
 * Protocols: `bittorrent`, `tls`, `http`.
 * Ports: `443`, `1000-2000`, comma separated.
 */
data class RouteRule(
    val id: Long,
    val name: String,
    val enabled: Boolean = true,
    val domains: List<String> = emptyList(),
    val ips: List<String> = emptyList(),
    val protocols: List<String> = emptyList(),
    val ports: String = "",
    val outbound: RouteOutbound = RouteOutbound.PROXY
) {
    val isEmpty: Boolean
        get() = domains.isEmpty() && ips.isEmpty() && protocols.isEmpty() && ports.isBlank()

    /** The lines a rule card shows: every condition, one per line. */
    fun summaryLines(): List<String> = buildList {
        addAll(domains)
        addAll(ips)
        if (protocols.isNotEmpty()) add("protocol: " + protocols.joinToString(", "))
        if (ports.isNotBlank()) add("port: $ports")
    }

    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("name", name)
        .put("enabled", enabled)
        .put("domains", JSONArray(domains))
        .put("ips", JSONArray(ips))
        .put("protocols", JSONArray(protocols))
        .put("ports", ports)
        .put("outbound", outbound.value)

    companion object {
        fun fromJson(o: JSONObject): RouteRule = RouteRule(
            id = o.optLong("id"),
            name = o.optString("name"),
            enabled = o.optBoolean("enabled", true),
            domains = o.optJSONArray("domains").strings(),
            ips = o.optJSONArray("ips").strings(),
            protocols = o.optJSONArray("protocols").strings(),
            ports = o.optString("ports"),
            outbound = RouteOutbound.fromValue(o.optString("outbound"))
        )

        /** One entry per non-blank line, trimmed; what the rule editor stores. */
        fun splitLines(text: String): List<String> =
            text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.distinct().toList()

        private fun JSONArray?.strings(): List<String> {
            if (this == null) return emptyList()
            return (0 until length()).mapNotNull { optString(it).trim().ifEmpty { null } }
        }
    }
}
