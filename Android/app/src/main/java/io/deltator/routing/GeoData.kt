package io.deltator.routing

import android.content.Context
import io.deltator.util.AppLog as Log
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.util.zip.GZIPInputStream

/**
 * Reads `geosite:` and `geoip:` lists.
 *
 * Geosite comes from a v2ray `geosite.dat`: the copy the user downloaded with
 * "Update rules" when there is one, else the trimmed copy bundled in the APK at
 * build time. Geoip comes from a downloaded `geoip.dat` when it carries the code
 * (runetfreedom ships special lists like `ru-blocked` there), else from the
 * country range table the APK already carries for Tor (`geoip/country.csv.gz`),
 * so every country code works offline. `geoip:private` is built in.
 */
object GeoData {
    private const val TAG = "GeoData"
    const val GEOSITE_FILE = "geosite.dat"
    const val GEOIP_FILE = "geoip.dat"
    const val ASSET_GEOSITE = "geo/geosite.dat"
    const val ASSET_GEOIP = "geo/geoip.dat"
    private const val ASSET_COUNTRY_TABLE = "geoip/country.csv.gz"
    private const val CACHE_VERSION = 1

    // Domain types, as numbered in v2ray's router.proto.
    const val TYPE_KEYWORD = 0
    const val TYPE_REGEX = 1
    const val TYPE_DOMAIN = 2
    const val TYPE_FULL = 3

    class Domain(val type: Int, val value: String)

    fun dir(context: Context): File = File(context.filesDir, "geo").apply { mkdirs() }

    /**
     * Domains for each wanted `code[@attr]` spec (lower case, no `geosite:`).
     * A spec missing from the data is absent from the result.
     */
    fun loadGeosite(context: Context, specs: Set<String>): Map<String, List<Domain>> {
        if (specs.isEmpty()) return emptyMap()
        val downloaded = File(dir(context), GEOSITE_FILE)
        val sources = buildList<() -> InputStream> {
            if (downloaded.isFile) add { downloaded.inputStream() }
            add { context.assets.open(ASSET_GEOSITE) }
        }
        return loadGeosite(sources, specs)
    }

    /** [loadGeosite] over explicit sources, tried in order per code. */
    internal fun loadGeosite(sources: List<() -> InputStream>, specs: Set<String>): Map<String, List<Domain>> {
        val byCode = specs.groupBy { it.substringBefore('@') }
        val out = HashMap<String, List<Domain>>()
        val missing = byCode.keys.toMutableSet()
        for (open in sources) {
            if (missing.isEmpty()) break
            try {
                open().use { raw ->
                    forEachEntry(raw, missing) { code, _, body ->
                        val domains = parseGeoSite(body)
                        for (spec in byCode[code].orEmpty()) out[spec] = filterAttrs(domains, spec)
                        missing -= code
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "geosite source unreadable: ${e.message}")
            }
        }
        if (missing.isNotEmpty()) Log.w(TAG, "geosite codes not found: ${missing.joinToString()}")
        return out
    }

    /** Ranges for each wanted code (lower case, no `geoip:`). */
    fun loadGeoip(context: Context, codes: Set<String>): Map<String, IpSet> {
        if (codes.isEmpty()) return emptyMap()
        val downloaded = File(dir(context), GEOIP_FILE)
        val sources = buildList<() -> InputStream> {
            if (downloaded.isFile) add { downloaded.inputStream() }
            add { context.assets.open(ASSET_GEOIP) }
        }
        val out = HashMap(loadGeoip(sources, codes))
        val missing = codes.toMutableSet().apply { removeAll(out.keys) }
        val countries = missing.filter { it.length == 2 }.toSet()
        if (countries.isNotEmpty()) {
            out += countryRanges(context, countries)
            missing -= out.keys
        }
        if (missing.isNotEmpty()) Log.w(TAG, "geoip codes not found: ${missing.joinToString()}")
        return out
    }

    /** geoip.dat lookups over explicit sources; `private` is built in. */
    internal fun loadGeoip(sources: List<() -> InputStream>, codes: Set<String>): Map<String, IpSet> {
        val out = HashMap<String, IpSet>()
        val missing = codes.toMutableSet()
        if (missing.remove("private")) out["private"] = IpSet.PRIVATE
        for (open in sources) {
            if (missing.isEmpty()) break
            try {
                open().use { raw ->
                    forEachEntry(raw, missing.toSet()) { code, _, body ->
                        out[code] = parseGeoIp(body)
                        missing -= code
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "geoip source unreadable: ${e.message}")
            }
        }
        return out
    }

    // ---- v2ray .dat (protobuf) ----

    /**
     * Walk the top-level `repeated entry = 1` list and hand over the body of every
     * entry whose code (field 1, always written first) is in [wanted]. Everything
     * else is skipped by length without being parsed, which is what keeps a
     * multi-megabyte geosite.dat cheap to search.
     */
    fun forEachEntry(
        raw: InputStream,
        wanted: Set<String>,
        onEntry: (code: String, codeBytes: ByteArray, rest: ByteArray) -> Unit
    ) {
        val r = PbReader(BufferedInputStream(raw, 1 shl 16))
        var left = wanted.size
        while (left > 0) {
            val tag = r.varintOrEof() ?: return
            if (tag != 0x0AL) { r.skipField(tag); continue }
            val len = r.varint()
            val codeTag = r.varint()
            if (codeTag != 0x0AL) { r.skip(len - sizeOfVarint(codeTag)); continue }
            val codeLen = r.varint().toInt()
            val codeBytes = r.bytes(codeLen)
            val code = String(codeBytes, Charsets.UTF_8).lowercase()
            val rest = len - sizeOfVarint(codeTag) - sizeOfVarint(codeLen.toLong()) - codeLen
            if (code in wanted) {
                onEntry(code, codeBytes, r.bytes(rest.toInt()))
                left--
            } else {
                r.skip(rest)
            }
        }
    }

    /** Write one top-level entry back in the wire format [forEachEntry] reads. */
    fun writeEntry(out: java.io.OutputStream, codeBytes: ByteArray, rest: ByteArray) {
        val inner = 1 + sizeOfVarint(codeBytes.size.toLong()) + codeBytes.size + rest.size
        out.write(0x0A)
        writeVarint(out, inner)
        out.write(0x0A)
        writeVarint(out, codeBytes.size.toLong())
        out.write(codeBytes)
        out.write(rest)
    }

    private fun writeVarint(out: java.io.OutputStream, value: Long) {
        var v = value
        while (v >= 0x80) { out.write(((v and 0x7F) or 0x80).toInt()); v = v ushr 7 }
        out.write(v.toInt())
    }

    private fun sizeOfVarint(v: Long): Long {
        var n = 1L
        var x = v ushr 7
        while (x != 0L) { n++; x = x ushr 7 }
        return n
    }

    private class RawDomain(val type: Int, val value: String, val attrs: Set<String>)

    private fun parseGeoSite(body: ByteArray): List<RawDomain> {
        val r = PbReader(body.inputStream())
        val out = ArrayList<RawDomain>()
        while (true) {
            val tag = r.varintOrEof() ?: break
            if (tag != 0x12L) { r.skipField(tag); continue }
            val d = PbReader(r.bytes(r.varint().toInt()).inputStream())
            var type = TYPE_KEYWORD
            var value = ""
            var attrs: MutableSet<String>? = null
            while (true) {
                val t = d.varintOrEof() ?: break
                when (t) {
                    0x08L -> type = d.varint().toInt()
                    0x12L -> value = String(d.bytes(d.varint().toInt()), Charsets.UTF_8)
                    0x1AL -> {
                        val a = PbReader(d.bytes(d.varint().toInt()).inputStream())
                        while (true) {
                            val at = a.varintOrEof() ?: break
                            if (at == 0x0AL) {
                                val key = String(a.bytes(a.varint().toInt()), Charsets.UTF_8)
                                (attrs ?: HashSet<String>().also { attrs = it }).add(key.lowercase())
                            } else a.skipField(at)
                        }
                    }
                    else -> d.skipField(t)
                }
            }
            if (value.isNotEmpty()) out += RawDomain(type, value, attrs ?: emptySet())
        }
        return out
    }

    /** `code@ads` keeps entries carrying `ads`; `code@!cn` drops entries carrying `cn`. */
    private fun filterAttrs(domains: List<RawDomain>, spec: String): List<Domain> {
        val filters = spec.split('@').drop(1).filter { it.isNotEmpty() }
        return domains.asSequence()
            .filter { d ->
                filters.all { f ->
                    if (f.startsWith('!')) f.substring(1) !in d.attrs else f in d.attrs
                }
            }
            .map { Domain(it.type, it.value) }
            .toList()
    }

    private fun parseGeoIp(body: ByteArray): IpSet {
        val r = PbReader(body.inputStream())
        val b = IpSet.Builder()
        while (true) {
            val tag = r.varintOrEof() ?: break
            if (tag != 0x12L) { r.skipField(tag); continue }
            val c = PbReader(r.bytes(r.varint().toInt()).inputStream())
            var ip: ByteArray? = null
            var prefix = 0
            while (true) {
                val t = c.varintOrEof() ?: break
                when (t) {
                    0x0AL -> ip = c.bytes(c.varint().toInt())
                    0x10L -> prefix = c.varint().toInt()
                    else -> c.skipField(t)
                }
            }
            ip?.let { b.addCidr(it, prefix) }
        }
        return b.build()
    }

    // ---- bundled country table ----

    /**
     * Country ranges from `country.csv.gz`. The table is 31 MB unpacked, so each
     * country is cut out once and cached in a small binary file; the cache is
     * tied to the installed APK so an update with a newer table rebuilds it.
     */
    private fun countryRanges(context: Context, codes: Set<String>): Map<String, IpSet> {
        val cacheDir = File(dir(context), "cache").apply { mkdirs() }
        val stamp = apkStamp(context)
        val out = HashMap<String, IpSet>()
        val toBuild = HashSet<String>()
        for (cc in codes) {
            val cached = readCache(File(cacheDir, "$cc.bin"), stamp)
            if (cached != null) out[cc] = cached else toBuild += cc
        }
        if (toBuild.isEmpty()) return out

        val builders = toBuild.associateWith { IpSet.Builder() }
        val upper = toBuild.associateBy { it.uppercase() }
        try {
            GZIPInputStream(context.assets.open(ASSET_COUNTRY_TABLE), 1 shl 16)
                .bufferedReader(Charsets.UTF_8).useLines { lines ->
                    for (line in lines) {
                        val c2 = line.lastIndexOf(',')
                        if (c2 < 0 || line.length - c2 != 3) continue
                        val cc = upper[line.substring(c2 + 1)] ?: continue
                        val c1 = line.indexOf(',')
                        if (c1 <= 0 || c1 >= c2) continue
                        val lo = parseIp(line.substring(0, c1)) ?: continue
                        val hi = parseIp(line.substring(c1 + 1, c2)) ?: continue
                        builders.getValue(cc).addRange(lo, hi)
                    }
                }
        } catch (e: Exception) {
            Log.e(TAG, "country table unreadable: ${e.message}")
            return out
        }
        for ((cc, b) in builders) {
            val set = b.build()
            out[cc] = set
            writeCache(File(cacheDir, "$cc.bin"), stamp, set)
            Log.i(TAG, "geoip:$cc built from country table: ${set.v4Count} v4 / ${set.v6Count} v6 ranges")
        }
        return out
    }

    private fun apkStamp(context: Context): Long = try {
        context.packageManager.getPackageInfo(context.packageName, 0).lastUpdateTime
    } catch (_: Exception) {
        0L
    }

    private fun readCache(file: File, stamp: Long): IpSet? {
        if (!file.isFile) return null
        return try {
            DataInputStream(file.inputStream().buffered()).use { inp ->
                if (inp.readInt() != CACHE_VERSION || inp.readLong() != stamp) return null
                IpSet.read(inp)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun writeCache(file: File, stamp: Long, set: IpSet) {
        try {
            val tmp = File(file.path + ".tmp")
            DataOutputStream(tmp.outputStream().buffered()).use { out ->
                out.writeInt(CACHE_VERSION)
                out.writeLong(stamp)
                set.write(out)
            }
            if (!tmp.renameTo(file)) { tmp.copyTo(file, true); tmp.delete() }
        } catch (e: Exception) {
            Log.w(TAG, "geoip cache write failed: ${e.message}")
        }
    }

    /** A literal IPv4/IPv6 address as raw bytes; never does a DNS lookup. */
    fun parseIp(text: String): ByteArray? {
        val s = text.trim()
        if (s.isEmpty()) return null
        if (':' !in s) return parseIpv4(s)
        if (!s.all { it.isLetterOrDigit() || it == ':' || it == '.' }) return null
        return try { InetAddress.getByName(s).address } catch (_: Exception) { null }
    }

    private fun parseIpv4(s: String): ByteArray? {
        val out = ByteArray(4)
        var part = 0
        var value = -1
        for (ch in s) {
            if (ch == '.') {
                if (value < 0 || part == 3) return null
                out[part++] = value.toByte()
                value = -1
            } else {
                val d = ch - '0'
                if (d !in 0..9) return null
                value = if (value < 0) d else value * 10 + d
                if (value > 255) return null
            }
        }
        if (value < 0 || part != 3) return null
        out[3] = value.toByte()
        return out
    }
}

/** Minimal protobuf wire reader: just what the two .dat formats need. */
private class PbReader(private val input: InputStream) {

    fun varintOrEof(): Long? {
        val first = input.read()
        if (first < 0) return null
        return continueVarint(first)
    }

    fun varint(): Long {
        val first = input.read()
        if (first < 0) throw EOFException()
        return continueVarint(first)
    }

    private fun continueVarint(first: Int): Long {
        var result = (first and 0x7F).toLong()
        var b = first
        var shift = 7
        while (b and 0x80 != 0) {
            b = input.read()
            if (b < 0) throw EOFException()
            result = result or ((b and 0x7F).toLong() shl shift)
            shift += 7
        }
        return result
    }

    fun bytes(n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(buf, off, n - off)
            if (r < 0) throw EOFException()
            off += r
        }
        return buf
    }

    fun skip(n: Long) {
        var left = n
        while (left > 0) {
            val s = input.skip(left)
            if (s <= 0) {
                if (input.read() < 0) throw EOFException()
                left--
            } else left -= s
        }
    }

    fun skipField(tag: Long) {
        when ((tag and 7).toInt()) {
            0 -> varint()
            1 -> skip(8)
            2 -> skip(varint())
            5 -> skip(4)
            else -> throw IllegalStateException("bad wire type in $tag")
        }
    }
}
