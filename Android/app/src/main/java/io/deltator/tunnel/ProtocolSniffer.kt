package io.deltator.tunnel

import io.deltator.util.AppLog as Log
import java.io.InputStream
import java.net.SocketTimeoutException

/**
 * Looks at the first bytes a client sends to learn where it is going and what it
 * speaks: the TLS SNI, the HTTP Host header, or a BitTorrent handshake.
 *
 * Used for routing when hev-socks5-tunnel hands over a bare IP (the TUN only
 * sees addresses). The bytes read here are returned so the caller can replay
 * them to whichever upstream it picks.
 */
object ProtocolSniffer {
    private const val TAG = "ProtocolSniffer"

    /**
     * A ClientHello carrying a post-quantum key share is about 1.8 KB and often
     * arrives in two TCP segments, so a single read used to see half a record
     * and give up. Reads continue until the record is complete, up to this size.
     */
    private const val MAX_SNIFF_SIZE = 16 * 1024

    const val PROTO_TLS = "tls"
    const val PROTO_HTTP = "http"
    const val PROTO_BITTORRENT = "bittorrent"

    class SniffResult(
        val domain: String?,
        val protocol: String?,
        val bufferedData: ByteArray,
        val bufferedLength: Int
    )

    private val HTTP_METHODS = arrayOf(
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    ).map { it.toByteArray(Charsets.US_ASCII) }

    private val BT_HANDSHAKE = "\u0013BitTorrent protocol".toByteArray(Charsets.US_ASCII)

    /**
     * Read what the client sends first. The socket's read timeout bounds the
     * wait, so server-first protocols (SSH, SMTP, ...) cost at most that long
     * and then go on unsniffed.
     */
    fun sniff(clientInput: InputStream): SniffResult {
        var buffer = ByteArray(2048)
        var len = 0
        try {
            while (len < MAX_SNIFF_SIZE) {
                if (len == buffer.size) buffer = buffer.copyOf(minOf(buffer.size * 2, MAX_SNIFF_SIZE))
                val n = clientInput.read(buffer, len, buffer.size - len)
                if (n <= 0) break
                len += n
                if (!needMore(buffer, len)) break
            }
        } catch (_: SocketTimeoutException) {
            // Nothing more within the window; decide on what arrived.
        } catch (e: Exception) {
            Log.w(TAG, "Sniff read error: ${e.message}")
        }
        if (len == 0) return SniffResult(null, null, buffer, 0)

        extractTlsSni(buffer, len)?.let { return SniffResult(it, PROTO_TLS, buffer, len) }
        if (isTlsHandshake(buffer, len)) return SniffResult(null, PROTO_TLS, buffer, len)
        if (startsWithAny(buffer, len, HTTP_METHODS)) {
            return SniffResult(extractHttpHost(buffer, len), PROTO_HTTP, buffer, len)
        }
        if (startsWith(buffer, len, BT_HANDSHAKE)) return SniffResult(null, PROTO_BITTORRENT, buffer, len)
        return SniffResult(null, null, buffer, len)
    }

    /** Whether the bytes so far are the start of something that is not complete yet. */
    private fun needMore(buf: ByteArray, len: Int): Boolean {
        if (isTlsHandshake(buf, len)) {
            if (len < 5) return true
            val recordLength = ((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)
            return len < 5 + recordLength
        }
        if (startsWithAny(buf, len, HTTP_METHODS)) {
            // Headers end at the first blank line.
            for (i in 3 until len) {
                if (buf[i - 3] == '\r'.code.toByte() && buf[i - 2] == '\n'.code.toByte() &&
                    buf[i - 1] == '\r'.code.toByte() && buf[i] == '\n'.code.toByte()
                ) return false
            }
            return true
        }
        return len < BT_HANDSHAKE.size && startsWith(BT_HANDSHAKE, BT_HANDSHAKE.size, buf.copyOf(len))
    }

    private fun isTlsHandshake(buf: ByteArray, len: Int): Boolean =
        len >= 1 && buf[0].toInt() == 0x16 && (len < 2 || buf[1].toInt() == 0x03)

    private fun startsWith(buf: ByteArray, len: Int, prefix: ByteArray): Boolean {
        if (len < prefix.size) return false
        for (i in prefix.indices) if (buf[i] != prefix[i]) return false
        return true
    }

    private fun startsWithAny(buf: ByteArray, len: Int, prefixes: List<ByteArray>): Boolean =
        prefixes.any { p -> startsWith(buf, len, p) || (len < p.size && startsWith(p, p.size, buf.copyOf(len))) }

    /**
     * SNI from a TLS ClientHello:
     * record header (5) | handshake header (4) | version (2) | random (32) |
     * session id | cipher suites | compression | extensions, where extension 0
     * holds the server name list.
     */
    private fun extractTlsSni(buf: ByteArray, len: Int): String? {
        if (len < 44 || buf[0].toInt() and 0xFF != 0x16 || buf[5].toInt() and 0xFF != 0x01) return null
        val recordEnd = minOf(len, 5 + (((buf[3].toInt() and 0xFF) shl 8) or (buf[4].toInt() and 0xFF)))

        var pos = 43
        if (pos >= recordEnd) return null
        pos += 1 + (buf[pos].toInt() and 0xFF)                       // session id
        if (pos + 2 > recordEnd) return null
        pos += 2 + u16(buf, pos)                                       // cipher suites
        if (pos >= recordEnd) return null
        pos += 1 + (buf[pos].toInt() and 0xFF)                         // compression
        if (pos + 2 > recordEnd) return null
        val extensionsEnd = minOf(recordEnd, pos + 2 + u16(buf, pos))
        pos += 2

        while (pos + 4 <= extensionsEnd) {
            val type = u16(buf, pos)
            val extLen = u16(buf, pos + 2)
            pos += 4
            if (type == 0x0000) {
                var p = pos + 2                                        // skip list length
                val end = minOf(extensionsEnd, pos + extLen)
                while (p + 3 <= end) {
                    val nameType = buf[p].toInt() and 0xFF
                    val nameLen = u16(buf, p + 1)
                    p += 3
                    if (p + nameLen > end) return null
                    if (nameType == 0 && nameLen > 0) {
                        return String(buf, p, nameLen, Charsets.US_ASCII).lowercase()
                    }
                    p += nameLen
                }
                return null
            }
            pos += extLen
        }
        return null
    }

    private fun u16(buf: ByteArray, pos: Int): Int =
        ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)

    /** Host header from an HTTP request, without a port. */
    private fun extractHttpHost(buf: ByteArray, len: Int): String? {
        val text = String(buf, 0, len, Charsets.ISO_8859_1)
        val hostIdx = text.indexOf("\r\nHost:", ignoreCase = true)
        if (hostIdx < 0) return null
        val valueStart = hostIdx + 7
        val lineEnd = text.indexOf("\r\n", valueStart).let { if (it < 0) text.length else it }
        var host = text.substring(valueStart, lineEnd).trim()
        if (host.startsWith('[')) {
            // [v6]:port
            host = host.substringAfter('[').substringBefore(']')
        } else {
            val colon = host.lastIndexOf(':')
            if (colon > 0 && host.indexOf(':') == colon && host.substring(colon + 1).all { it.isDigit() }) {
                host = host.substring(0, colon)
            }
        }
        return host.lowercase().ifEmpty { null }
    }
}
