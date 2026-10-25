package io.deltator.routing

import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * A set of IPv4 and IPv6 ranges, sorted and merged so a lookup is one binary
 * search. Merging matters: with overlapping or nested ranges, "the last range
 * starting at or below the address" is not necessarily the one containing it.
 *
 * IPv4 bounds are plain longs; IPv6 bounds are (high, low) pairs of longs
 * compared unsigned.
 */
class IpSet private constructor(
    private val v4Start: LongArray,
    private val v4End: LongArray,
    private val v6StartHi: LongArray,
    private val v6StartLo: LongArray,
    private val v6EndHi: LongArray,
    private val v6EndLo: LongArray
) {
    val v4Count get() = v4Start.size
    val v6Count get() = v6StartHi.size
    val isEmpty get() = v4Count == 0 && v6Count == 0

    fun contains(addr: ByteArray): Boolean = when (addr.size) {
        4 -> containsV4(v4Long(addr))
        16 -> {
            // IPv4-mapped addresses (::ffff:a.b.c.d) are IPv4 for matching purposes.
            if (isV4Mapped(addr)) containsV4(v4Long(addr, 12))
            else containsV6(long(addr, 0), long(addr, 8))
        }
        else -> false
    }

    private fun containsV4(ip: Long): Boolean {
        var lo = 0
        var hi = v4Start.size - 1
        var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (v4Start[mid] <= ip) { found = mid; lo = mid + 1 } else hi = mid - 1
        }
        return found >= 0 && ip <= v4End[found]
    }

    private fun containsV6(h: Long, l: Long): Boolean {
        var lo = 0
        var hi = v6StartHi.size - 1
        var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (cmp(v6StartHi[mid], v6StartLo[mid], h, l) <= 0) { found = mid; lo = mid + 1 } else hi = mid - 1
        }
        return found >= 0 && cmp(h, l, v6EndHi[found], v6EndLo[found]) <= 0
    }

    fun write(out: DataOutputStream) {
        out.writeInt(v4Start.size)
        for (i in v4Start.indices) { out.writeLong(v4Start[i]); out.writeLong(v4End[i]) }
        out.writeInt(v6StartHi.size)
        for (i in v6StartHi.indices) {
            out.writeLong(v6StartHi[i]); out.writeLong(v6StartLo[i])
            out.writeLong(v6EndHi[i]); out.writeLong(v6EndLo[i])
        }
    }

    class Builder {
        private val v4 = ArrayList<LongArray>()
        private val v6 = ArrayList<LongArray>()

        fun addAll(other: IpSet): Builder {
            for (i in other.v4Start.indices) v4 += longArrayOf(other.v4Start[i], other.v4End[i])
            for (i in other.v6StartHi.indices) {
                v6 += longArrayOf(other.v6StartHi[i], other.v6StartLo[i], other.v6EndHi[i], other.v6EndLo[i])
            }
            return this
        }

        fun addRange(lo: ByteArray, hi: ByteArray) {
            if (lo.size != hi.size) return
            when (lo.size) {
                4 -> {
                    val a = v4Long(lo); val b = v4Long(hi)
                    if (a <= b) v4 += longArrayOf(a, b)
                }
                16 -> {
                    val r = longArrayOf(long(lo, 0), long(lo, 8), long(hi, 0), long(hi, 8))
                    if (cmp(r[0], r[1], r[2], r[3]) <= 0) v6 += r
                }
            }
        }

        fun addCidr(ip: ByteArray, prefix: Int) {
            val bits = ip.size * 8
            if (prefix !in 0..bits || (ip.size != 4 && ip.size != 16)) return
            val lo = ip.copyOf()
            val hi = ip.copyOf()
            for (bit in prefix until bits) {
                val i = bit / 8
                val mask = 0x80 ushr (bit % 8)
                lo[i] = (lo[i].toInt() and mask.inv()).toByte()
                hi[i] = (hi[i].toInt() or mask).toByte()
            }
            addRange(lo, hi)
        }

        /** `1.2.3.0/24`, `2a00::/16` or a single address; false when unparsable. */
        fun addText(text: String): Boolean {
            val slash = text.indexOf('/')
            val ip = GeoData.parseIp(if (slash < 0) text else text.substring(0, slash)) ?: return false
            val prefix = if (slash < 0) ip.size * 8 else text.substring(slash + 1).trim().toIntOrNull() ?: return false
            if (prefix !in 0..ip.size * 8) return false
            addCidr(ip, prefix)
            return true
        }

        fun build(): IpSet {
            v4.sortBy { it[0] }
            val s4 = ArrayList<Long>(v4.size)
            val e4 = ArrayList<Long>(v4.size)
            for (r in v4) {
                if (s4.isNotEmpty() && r[0] <= e4.last() + 1) {
                    if (r[1] > e4.last()) e4[e4.size - 1] = r[1]
                } else { s4 += r[0]; e4 += r[1] }
            }
            v6.sortWith { a, b -> cmp(a[0], a[1], b[0], b[1]) }
            val m6 = ArrayList<LongArray>(v6.size)
            for (r in v6) {
                val last = m6.lastOrNull()
                if (last != null && adjacentOrOverlap(last, r)) {
                    if (cmp(r[2], r[3], last[2], last[3]) > 0) { last[2] = r[2]; last[3] = r[3] }
                } else m6 += r.copyOf()
            }
            return IpSet(
                s4.toLongArray(), e4.toLongArray(),
                LongArray(m6.size) { m6[it][0] }, LongArray(m6.size) { m6[it][1] },
                LongArray(m6.size) { m6[it][2] }, LongArray(m6.size) { m6[it][3] }
            )
        }

        /** Does [r] start at or before one past the end of [last]? */
        private fun adjacentOrOverlap(last: LongArray, r: LongArray): Boolean {
            if (cmp(r[0], r[1], last[2], last[3]) <= 0) return true
            // last end + 1 == r start
            val lo = last[3] + 1
            val hi = if (lo == 0L) last[2] + 1 else last[2]
            return hi == r[0] && lo == r[1]
        }
    }

    companion object {
        val EMPTY = Builder().build()

        /** Loopback, private, link-local, CGNAT, multicast and reserved space. */
        val PRIVATE: IpSet = Builder().apply {
            listOf(
                "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
                "224.0.0.0/4", "240.0.0.0/4",
                "::/127", "fc00::/7", "fe80::/10", "ff00::/8"
            ).forEach { addText(it) }
        }.build()

        fun read(inp: DataInputStream): IpSet {
            val n4 = inp.readInt()
            val s4 = LongArray(n4); val e4 = LongArray(n4)
            for (i in 0 until n4) { s4[i] = inp.readLong(); e4[i] = inp.readLong() }
            val n6 = inp.readInt()
            val sh = LongArray(n6); val sl = LongArray(n6); val eh = LongArray(n6); val el = LongArray(n6)
            for (i in 0 until n6) {
                sh[i] = inp.readLong(); sl[i] = inp.readLong(); eh[i] = inp.readLong(); el[i] = inp.readLong()
            }
            return IpSet(s4, e4, sh, sl, eh, el)
        }

        private fun v4Long(b: ByteArray, off: Int = 0): Long =
            ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
                ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

        private fun long(b: ByteArray, off: Int): Long {
            var v = 0L
            for (i in off until off + 8) v = (v shl 8) or (b[i].toLong() and 0xFF)
            return v
        }

        private fun isV4Mapped(b: ByteArray): Boolean {
            for (i in 0 until 10) if (b[i].toInt() != 0) return false
            return b[10].toInt() == -1 && b[11].toInt() == -1
        }

        private fun cmp(ah: Long, al: Long, bh: Long, bl: Long): Int {
            val c = java.lang.Long.compareUnsigned(ah, bh)
            return if (c != 0) c else java.lang.Long.compareUnsigned(al, bl)
        }
    }
}
