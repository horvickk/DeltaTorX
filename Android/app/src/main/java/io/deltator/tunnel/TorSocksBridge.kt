package io.deltator.tunnel

import io.deltator.routing.GeoData
import io.deltator.routing.RouteOutbound
import io.deltator.routing.Router
import io.deltator.util.AppLog as Log
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SOCKS5 bridge for Snowflake (Tor) tunnel type.
 *
 * Sits between hev-socks5-tunnel and Tor's SOCKS5 proxy:
 * - CONNECT (0x01): chains to Tor SOCKS5 (no auth)
 * - FWD_UDP (0x05) DNS (port 53): DNS-over-TCP through Tor SOCKS5 CONNECT
 * - FWD_UDP (0x05) non-DNS: sent straight out when a route says bypass,
 *   otherwise dropped (Tor carries no UDP; browsers fall back to TCP)
 *
 * Routing: with a [Router] installed every connection is matched against the
 * route list (domain from the request or sniffed, IP, port, protocol) and goes
 * through Tor, straight out, or nowhere.
 *
 * DNS optimization:
 * - Concurrent: 8-thread pool for parallel DNS resolution
 * - Cached: answers are reused for 5 minutes, so a busy page rarely re-asks
 * - Failover: several resolvers in turn, all reached over Tor
 *
 * Traffic flow:
 * App -> TUN -> hev-socks5-tunnel -> TorSocksBridge (proxyPort)
 *   TCP: -> SOCKS5 CONNECT (no auth) -> Tor SOCKS5 (proxyPort+1) -> Tor circuit -> Server
 *   DNS: -> FWD_UDP -> DNS-over-TCP via Tor SOCKS5 CONNECT -> resolver:53
 */
object TorSocksBridge {
    private const val TAG = "TorSocksBridge"
    @Volatile var debugLogging = false
    /**
     * The compiled route list. Swapping it applies to new connections at once;
     * cached DNS answers are dropped with it, because a name that now bypasses
     * Tor must be looked up locally again (and vice versa).
     */
    @Volatile var router: Router = Router.DISABLED
        set(value) {
            field = value
            dnsCache.clear()
        }

    /**
     * Resolvers of the underlying network, for names a route sends around Tor.
     * Set by the VPN service from the non-VPN network's link properties.
     */
    @Volatile var directDnsServers: List<InetAddress> = emptyList()

    /**
     * Whether the underlying network can reach the internet over IPv6. The VPN
     * captures IPv6, so apps ask for IPv6 addresses; on a network without IPv6
     * a bypassed connection must not be handed one, or it can only fail.
     */
    @Volatile var directIpv6: Boolean = false
    private fun logd(msg: String) { if (debugLogging) Log.d(TAG, msg) }
    private const val BIND_MAX_RETRIES = 10
    private const val BIND_RETRY_DELAY_MS = 200L
    private const val BUFFER_SIZE = 32768
    private const val TCP_CONNECT_TIMEOUT_MS = 30000
    private const val DNS_TIMEOUT_MS = 15000
    private const val DNS_CACHE_TTL_MS = 300_000L
    /** How long a routed connection waits for the client's first bytes. */
    private const val SNIFF_TIMEOUT_MS = 1000
    private const val DIRECT_CONNECT_TIMEOUT_MS = 10_000
    private const val DIRECT_DNS_TIMEOUT_MS = 4000
    /** Tor waits for the exit before answering; a lookup rarely needs more. */
    private const val DNS_PORT_TIMEOUT_MS = 10_000
    private val LOOPBACK = byteArrayOf(127, 0, 0, 1)
    private val SOCKS_OK = byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
    private val SOCKS_NOT_ALLOWED = byteArrayOf(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
    private val SOCKS_REFUSED = byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
    /** Public resolvers for bypassed names when the network reports none. */
    private val FALLBACK_DIRECT_DNS = listOf(
        byteArrayOf(77, 88, 8, 8),      // Yandex
        byteArrayOf(1, 1, 1, 1),        // Cloudflare
        byteArrayOf(8, 8, 8, 8)         // Google
    ).map { InetAddress.getByAddress(it) }

    private var torHost: String = "127.0.0.1"
    private var torSocksPort: Int = 0
    @Volatile private var torDnsPort: Int = 0
    private var localAuthUsername: String? = null
    private var localAuthPassword: String? = null
    private var serverSocket: ServerSocket? = null
    private var acceptorThread: Thread? = null
    private val running = AtomicBoolean(false)
    private val connectionThreads = CopyOnWriteArrayList<Thread>()
    private var dnsExecutor = Executors.newFixedThreadPool(8)

    // DNS cache: query key (hex of query minus transaction ID) -> (response, expiry)
    private data class DnsCacheEntry(val response: ByteArray, val expiresAt: Long)
    private val dnsCache = ConcurrentHashMap<String, DnsCacheEntry>()

    fun start(
        torSocksPort: Int,
        torDnsPort: Int = 0,
        torHost: String = "127.0.0.1",
        listenPort: Int,
        listenHost: String = "127.0.0.1",
        localAuthUsername: String? = null,
        localAuthPassword: String? = null
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting Tor SOCKS5 bridge")
        Log.i(TAG, "  Tor SOCKS5: $torHost:$torSocksPort")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "  Local auth: ${if (!localAuthUsername.isNullOrEmpty()) "enabled" else "disabled"}")
        Log.i(TAG, "========================================")

        stop()
        this.torHost = torHost
        this.torSocksPort = torSocksPort
        this.torDnsPort = torDnsPort
        this.localAuthUsername = localAuthUsername
        this.localAuthPassword = localAuthPassword

        return try {
            val ss = bindServerSocket(listenHost, listenPort)
            serverSocket = ss
            running.set(true)

            acceptorThread = Thread({
                logd("Acceptor thread started")
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        val clientSocket = ss.accept()
                        handleConnection(clientSocket)
                    } catch (e: Exception) {
                        if (running.get()) {
                            Log.w(TAG, "Accept error: ${e.message}")
                        }
                    }
                }
                logd("Acceptor thread exited")
            }, "tor-bridge-acceptor").also { it.isDaemon = true; it.start() }

            Log.i(TAG, "Bridge started on $listenHost:$listenPort")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start bridge", e)
            stop()
            Result.failure(e)
        }
    }

    fun stop() {
        if (!running.getAndSet(false) && serverSocket == null) {
            return
        }
        logd("Stopping bridge...")

        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null

        acceptorThread?.interrupt()
        acceptorThread = null

        for (thread in connectionThreads) {
            thread.interrupt()
        }
        connectionThreads.clear()

        dnsExecutor.shutdownNow()
        dnsExecutor = Executors.newFixedThreadPool(8)

        dnsCache.clear()

        logd("Bridge stopped")
    }

    fun isRunning(): Boolean = running.get()

    /**
     * Send new connections to a different Tor SOCKS port without rebinding.
     *
     * The listener keeps its own port, so tun2socks and every app socket that was
     * already chained stay untouched: only connections opened from here on follow
     * the new runner. This is what makes a recovery invisible, the tunnel never
     * goes down while a replacement Tor boots on the same bridge.
     */
    fun repoint(torSocksPort: Int, torDnsPort: Int) {
        this.torDnsPort = torDnsPort
        if (this.torSocksPort != torSocksPort) {
            Log.i(TAG, "Repointing bridge: $torHost:${this.torSocksPort} -> $torHost:$torSocksPort")
            this.torSocksPort = torSocksPort
        }
        // Cached answers were resolved over the circuit that just went away, so
        // drop them: a recovery reuses the same runner port, and returning early
        // on an unchanged port used to keep up to five minutes of name mappings
        // that were resolved by the dead Tor.
        dnsCache.clear()
    }

    fun isClientHealthy(): Boolean {
        val ss = serverSocket ?: return false
        return running.get() && !ss.isClosed
    }

    private fun bindServerSocket(host: String, port: Int): ServerSocket {
        val ss = ServerSocket()
        ss.reuseAddress = true
        var lastException: java.net.BindException? = null
        repeat(BIND_MAX_RETRIES) { attempt ->
            try {
                ss.bind(InetSocketAddress(host, port))
                if (attempt > 0) Log.i(TAG, "Port $port bound after ${attempt + 1} attempts")
                return ss
            } catch (e: java.net.BindException) {
                lastException = e
                if (attempt < BIND_MAX_RETRIES - 1) {
                    Log.w(TAG, "Port $port in use, retrying in ${BIND_RETRY_DELAY_MS}ms (attempt ${attempt + 1}/$BIND_MAX_RETRIES)")
                    Thread.sleep(BIND_RETRY_DELAY_MS)
                }
            }
        }
        ss.close()
        throw lastException ?: java.net.BindException("Failed to bind to port $port")
    }

    private fun handleConnection(clientSocket: Socket) {
        val thread = Thread({
            try {
                clientSocket.use { socket ->
                    socket.soTimeout = 30000
                    socket.tcpNoDelay = true
                    val input = socket.getInputStream()
                    val output = socket.getOutputStream()

                    // SOCKS5 greeting
                    val version = input.read()
                    if (version == -1) {
                        // EOF — readiness probe or client closed immediately; not an error
                        return@Thread
                    }
                    if (version != 0x05) {
                        Log.w(TAG, "Invalid SOCKS5 version: $version")
                        return@Thread
                    }
                    val nMethods = input.read()
                    val methods = ByteArray(nMethods)
                    input.readFully(methods)

                    // Authenticate local client
                    if (!LocalProxyAuth.handleGreeting(methods, input, output, localAuthUsername, localAuthPassword)) {
                        return@Thread
                    }

                    // SOCKS5 request
                    val ver = input.read()
                    val cmd = input.read()
                    input.read() // reserved

                    if (ver != 0x05 || (cmd != 0x01 && cmd != 0x05)) {
                        output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        return@Thread
                    }

                    // Parse address
                    val addrType = input.read()
                    val destHost: String
                    val rawAddr: ByteArray

                    when (addrType) {
                        0x01 -> { // IPv4
                            val addr = ByteArray(4)
                            input.readFully(addr)
                            destHost = addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
                            rawAddr = byteArrayOf(0x01) + addr
                        }
                        0x03 -> { // Domain name
                            val len = input.read()
                            val domain = ByteArray(len)
                            input.readFully(domain)
                            destHost = String(domain)
                            rawAddr = byteArrayOf(0x03, len.toByte()) + domain
                        }
                        0x04 -> { // IPv6
                            val addr = ByteArray(16)
                            input.readFully(addr)
                            destHost = formatIpv6(addr)
                            rawAddr = byteArrayOf(0x04) + addr
                        }
                        else -> {
                            output.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                            output.flush()
                            return@Thread
                        }
                    }

                    val portHigh = input.read()
                    val portLow = input.read()
                    val destPort = (portHigh shl 8) or portLow
                    val portBytes = byteArrayOf(portHigh.toByte(), portLow.toByte())

                    // Handle FWD_UDP (cmd 0x05)
                    if (cmd == 0x05) {
                        socket.soTimeout = 0
                        handleFwdUdp(input, output)
                        return@Thread
                    }

                    // Handle CONNECT (cmd 0x01) — chain through Tor SOCKS5
                    handleConnect(destHost, destPort, rawAddr, portBytes, socket, input, output)
                }
            } catch (e: Exception) {
                if (running.get()) {
                    logd("Connection handler error: ${e.message}")
                }
            }
        }, "tor-bridge-handler")
        thread.isDaemon = true
        connectionThreads.add(thread)
        thread.start()

        connectionThreads.removeAll { !it.isAlive }
    }

    /**
     * Handle SOCKS5 CONNECT: through Tor, or as the route list says.
     */
    private fun handleConnect(
        destHost: String,
        destPort: Int,
        rawAddr: ByteArray,
        portBytes: ByteArray,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream
    ) {
        val r = router
        // Onion services only exist inside Tor: a placeholder address or an
        // onion name never goes anywhere else, whatever the route list says.
        if (r.enabled && !isOnion(destHost)) {
            handleConnectWithRouting(r, destHost, destPort, rawAddr, portBytes, clientSocket, clientInput, clientOutput)
            return
        }
        connectViaTor(destHost, destPort, rawAddr, portBytes, clientSocket, clientInput, clientOutput, sendReply = true)
    }

    /**
     * Route one CONNECT.
     *
     * The client's first bytes are only waited for when a rule needs them: a
     * protocol rule always does, a domain rule only when the request carries a
     * bare IP. Waiting means answering the SOCKS handshake first (the client
     * sends nothing before that), so a failure after the decision shows up as
     * the connection closing rather than as a SOCKS error.
     */
    private fun handleConnectWithRouting(
        r: Router,
        destHost: String,
        destPort: Int,
        rawAddr: ByteArray,
        portBytes: ByteArray,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream
    ) {
        val literal = GeoData.parseIp(destHost)
        var host: String? = if (literal == null) destHost else null
        var protocol: String? = null
        var sniffBuffer: ByteArray? = null
        var sniffLen = 0
        val earlyReply = r.wantsProtocol || (literal != null && r.wantsDomain)

        if (earlyReply) {
            clientOutput.write(SOCKS_OK)
            clientOutput.flush()
            clientSocket.soTimeout = SNIFF_TIMEOUT_MS
            val result = ProtocolSniffer.sniff(clientInput)
            if (result.domain != null) host = result.domain
            protocol = result.protocol
            sniffBuffer = result.bufferedData
            sniffLen = result.bufferedLength
        }
        clientSocket.soTimeout = 0
        val input = if (sniffLen > 0)
            SequenceInputStream(ByteArrayInputStream(sniffBuffer!!, 0, sniffLen), clientInput)
        else clientInput

        when (r.decide(host, literal, destPort, protocol)) {
            RouteOutbound.BLOCK -> {
                logd("CONNECT: blocked ${host ?: destHost}:$destPort")
                if (!earlyReply) {
                    clientOutput.write(SOCKS_NOT_ALLOWED)
                    clientOutput.flush()
                }
            }
            RouteOutbound.BYPASS -> {
                logd("CONNECT: bypass ${host ?: destHost}:$destPort (${protocol ?: "?"})")
                val direct = openDirect(destHost, destPort, literal)
                if (direct == null) {
                    // The client was already told the connection is up (the
                    // early reply), so failing here would surface as a dropped
                    // connection with no retry. Tor still gets the site there.
                    connectViaTor(destHost, destPort, rawAddr, portBytes, clientSocket, input, clientOutput, sendReply = !earlyReply)
                    return
                }
                if (!earlyReply) {
                    clientOutput.write(SOCKS_OK)
                    clientOutput.flush()
                }
                bridgeDirect(input, clientOutput, direct)
            }
            RouteOutbound.PROXY ->
                connectViaTor(destHost, destPort, rawAddr, portBytes, clientSocket, input, clientOutput, sendReply = !earlyReply)
        }
    }

    /**
     * A socket to [host]:[port] outside the tunnel, or null when that cannot
     * work. The app is excluded from its own VPN, so a plain socket leaves
     * through the underlying network.
     */
    private fun openDirect(host: String, port: Int, literal: ByteArray?): Socket? {
        if (literal?.size == 16 && !directIpv6) {
            Log.w(TAG, "bypass: $host is IPv6 but the network has no IPv6, using Tor")
            return null
        }
        return try {
            Socket().apply {
                connect(InetSocketAddress(host, port), DIRECT_CONNECT_TIMEOUT_MS)
                tcpNoDelay = true
            }
        } catch (e: Exception) {
            Log.w(TAG, "bypass: direct connection to $host:$port failed (${e.message}), using Tor")
            null
        }
    }

    /**
     * Connect through Tor SOCKS5 and bridge bidirectionally.
     * If [sendReply] is true, sends SOCKS5 success/failure replies to client.
     * If false, success reply was already sent (early reply for sniffing).
     */
    private fun connectViaTor(
        destHost: String,
        destPort: Int,
        rawAddr: ByteArray,
        portBytes: ByteArray,
        clientSocket: Socket,
        clientInput: InputStream,
        clientOutput: OutputStream,
        sendReply: Boolean
    ) {
        val remoteSocket: Socket
        try {
            remoteSocket = Socket()
            remoteSocket.connect(InetSocketAddress(torHost, torSocksPort), TCP_CONNECT_TIMEOUT_MS)
            remoteSocket.tcpNoDelay = true
        } catch (e: Exception) {
            logd("CONNECT: failed to connect to Tor SOCKS5: ${e.message}")
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }
            return
        }

        try {
            val remoteInput = remoteSocket.getInputStream()
            val remoteOutput = remoteSocket.getOutputStream()

            // SOCKS5 greeting to Tor (no auth)
            remoteOutput.write(byteArrayOf(0x05, 0x01, 0x00))
            remoteOutput.flush()

            val greetResp = ByteArray(2)
            remoteInput.readFully(greetResp)
            if (greetResp[0] != 0x05.toByte() || (greetResp[1].toInt() and 0xFF) == 0xFF) {
                Log.w(TAG, "CONNECT: Tor rejected greeting")
                if (sendReply) {
                    clientOutput.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                }
                remoteSocket.close()
                return
            }

            // SOCKS5 CONNECT request to Tor
            val connectReq = byteArrayOf(0x05, 0x01, 0x00) + rawAddr + portBytes
            remoteOutput.write(connectReq)
            remoteOutput.flush()

            // Read CONNECT response header
            val connRespHeader = ByteArray(4)
            remoteInput.readFully(connRespHeader)

            if (connRespHeader[1] != 0x00.toByte()) {
                logd("CONNECT: Tor rejected to $destHost:$destPort (rep=${connRespHeader[1]})")
                if (sendReply) {
                    clientOutput.write(byteArrayOf(0x05, connRespHeader[1], 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                }
                remoteSocket.close()
                return
            }

            // Read remaining response bytes based on address type
            when (connRespHeader[3].toInt() and 0xFF) {
                0x01 -> { val rest = ByteArray(6); remoteInput.readFully(rest) }
                0x03 -> { val len = remoteInput.read(); val rest = ByteArray(len + 2); remoteInput.readFully(rest) }
                0x04 -> { val rest = ByteArray(18); remoteInput.readFully(rest) }
            }

            logd("CONNECT: $destHost:$destPort OK (via Tor)")

            // Send success to hev-socks5-tunnel (if not already sent)
            if (sendReply) {
                clientOutput.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOutput.flush()
            }

            clientSocket.soTimeout = 0

            // Bridge bidirectionally
            remoteSocket.use { remote ->
                val t1 = Thread({
                    try {
                        copyStream(clientInput, remoteOutput)
                    } catch (_: Exception) {
                    } finally {
                        try { remoteOutput.close() } catch (_: Exception) {}
                    }
                }, "tor-bridge-c2s")
                t1.isDaemon = true
                t1.start()

                try {
                    copyStream(remoteInput, clientOutput)
                } catch (_: Exception) {
                } finally {
                    try { remote.close() } catch (_: Exception) {}
                    t1.interrupt()
                }
            }
        } catch (e: Exception) {
            logd("CONNECT: chain error for $destHost:$destPort: ${e.message}")
            if (sendReply) {
                try {
                    clientOutput.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    clientOutput.flush()
                } catch (_: Exception) {}
            }
            try { remoteSocket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Handle FWD_UDP (cmd 0x05) — same wire format as other bridges.
     * DNS (port 53): DNS-over-TCP through Tor SOCKS5 CONNECT, so no query ever
     * leaves the device in the clear, except names a route sends around Tor,
     * which are asked of the local network, and blocked names, which are
     * answered NXDOMAIN on the spot. Other UDP goes straight out when a route
     * says bypass and is dropped otherwise.
     *
     * DNS queries are dispatched to a thread pool for concurrent resolution.
     * Responses are cached for 5 minutes to keep repeat lookups off the wire.
     */
    private fun handleFwdUdp(input: InputStream, output: OutputStream) {
        output.write(SOCKS_OK)
        output.flush()

        logd("FWD_UDP session established")
        var relay: UdpDirectRelay? = null
        try {
            while (running.get() && !Thread.currentThread().isInterrupted) {
                val hdr = ByteArray(3)
                input.readFully(hdr)

                val datLen = ((hdr[0].toInt() and 0xFF) shl 8) or (hdr[1].toInt() and 0xFF)
                val hdrLen = hdr[2].toInt() and 0xFF
                val addrLen = hdrLen - 3

                if (addrLen <= 0 || datLen <= 0) {
                    Log.w(TAG, "FWD_UDP: invalid header (datLen=$datLen, hdrLen=$hdrLen)")
                    break
                }

                val addrBytes = ByteArray(addrLen)
                input.readFully(addrBytes)

                val payload = ByteArray(datLen)
                input.readFully(payload)

                val dest = parseSocksAddress(addrBytes)
                if (dest == null) {
                    Log.w(TAG, "FWD_UDP: failed to parse address")
                    continue
                }

                val r = router
                if (dest.second != 53) {
                    if (!r.enabled) continue
                    val ip = GeoData.parseIp(dest.first) ?: continue
                    val protocol = if (looksLikeBitTorrentUdp(payload)) ProtocolSniffer.PROTO_BITTORRENT else null
                    if (r.decide(null, ip, dest.second, protocol) != RouteOutbound.BYPASS) continue
                    try {
                        val rl = relay ?: UdpDirectRelay(output).also { relay = it }
                        rl.send(ip, dest.second, payload)
                    } catch (e: Exception) {
                        logd("FWD_UDP: direct send to ${dest.first}:${dest.second} failed: ${e.message}")
                    }
                    continue
                }

                // Payloads are fresh arrays per frame, so the worker can own them.
                dnsExecutor.submit {
                    try {
                        val response = answerDns(r, payload)
                        if (response != null && response.isNotEmpty()) {
                            val respHdr = byteArrayOf(
                                ((response.size shr 8) and 0xFF).toByte(),
                                (response.size and 0xFF).toByte(),
                                (3 + addrBytes.size).toByte()
                            )
                            synchronized(output) {
                                output.write(respHdr)
                                output.write(addrBytes)
                                output.write(response)
                                output.flush()
                            }
                        }
                    } catch (e: Exception) {
                        logd("FWD_UDP: DNS forward failed: ${e.message}")
                    }
                }
            }
        } finally {
            relay?.close()
        }

        logd("FWD_UDP session ended")
    }

    /** One DNS answer: cache, then the route list's verdict, then Tor. */
    private fun answerDns(r: Router, query: ByteArray): ByteArray? {
        getCachedDns(query)?.let { logd("DNS: cache hit"); return it }
        val name = dnsQuestionName(query)
        val verdict = if (r.enabled && name != null && !isOnion(name)) r.decideName(name) else null
        val response = when (verdict) {
            RouteOutbound.BLOCK -> return dnsNxdomain(query)
            RouteOutbound.BYPASS -> {
                // No IPv6 underneath: answer AAAA with "no such record" so the
                // app goes straight to IPv4 instead of trying an address that
                // can only fail.
                if (!directIpv6 && dnsQuestionType(query) == 28) return dnsNoData(query)
                resolveDirect(query) ?: resolveThroughTor(query)
            }
            else -> resolveThroughTor(query)
        }
        if (response != null) cacheDnsResponse(query, response)
        return response
    }

    /** The first question's name, or null for anything that is not a plain query. */
    private fun dnsQuestionName(q: ByteArray): String? {
        if (q.size < 17 || (q[2].toInt() and 0x80) != 0) return null
        if ((((q[4].toInt() and 0xFF) shl 8) or (q[5].toInt() and 0xFF)) < 1) return null
        val sb = StringBuilder()
        var pos = 12
        while (pos < q.size) {
            val n = q[pos].toInt() and 0xFF
            if (n == 0) return if (sb.isEmpty()) null else sb.toString()
            if (n and 0xC0 != 0 || pos + 1 + n > q.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(q, pos + 1, n, Charsets.ISO_8859_1))
            pos += 1 + n
        }
        return null
    }

    private val ONION_NET = io.deltator.routing.IpSet.Builder()
        .apply { addText(TorRunner.ONION_VIRTUAL_NET) }.build()

    /** An onion name, or one of the placeholder addresses Tor maps them to. */
    private fun isOnion(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        if (h.endsWith(".onion")) return true
        val ip = GeoData.parseIp(h) ?: return false
        return ONION_NET.contains(ip)
    }

    /** QTYPE of the first question, or -1. */
    private fun dnsQuestionType(q: ByteArray): Int {
        var pos = 12
        while (pos < q.size && q[pos].toInt() != 0) pos += 1 + (q[pos].toInt() and 0xFF)
        if (pos + 3 > q.size) return -1
        return ((q[pos + 1].toInt() and 0xFF) shl 8) or (q[pos + 2].toInt() and 0xFF)
    }

    /** NOERROR with no answers: the name exists, the record type does not. */
    private fun dnsNoData(query: ByteArray): ByteArray? =
        dnsNxdomain(query)?.also { it[3] = 0x80.toByte() }

    /** NXDOMAIN for [query]: header and question echoed, no records. */
    private fun dnsNxdomain(query: ByteArray): ByteArray? {
        var pos = 12
        while (pos < query.size && query[pos].toInt() != 0) pos += 1 + (query[pos].toInt() and 0xFF)
        val end = pos + 1 + 4
        if (end > query.size) return null
        val resp = query.copyOf(end)
        resp[2] = ((query[2].toInt() and 0x79) or 0x80).toByte()   // QR, keep opcode + RD
        resp[3] = 0x83.toByte()                                     // RA, NXDOMAIN
        resp[4] = 0; resp[5] = 1                                    // one question
        for (i in 6 until 12) resp[i] = 0
        return resp
    }

    /** Ask the underlying network's resolvers over plain UDP. */
    private fun resolveDirect(query: ByteArray): ByteArray? {
        val servers = directDnsServers.ifEmpty { FALLBACK_DIRECT_DNS }
        try {
            DatagramSocket().use { socket ->
                socket.soTimeout = DIRECT_DNS_TIMEOUT_MS / servers.size.coerceAtLeast(1)
                val buf = ByteArray(4096)
                for (server in servers) {
                    try {
                        socket.send(DatagramPacket(query, query.size, server, 53))
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
                        if (packet.length >= 12 && buf[0] == query[0] && buf[1] == query[1]) {
                            logd("DNS: resolved directly via ${server.hostAddress}")
                            return buf.copyOf(packet.length)
                        }
                    } catch (_: Exception) {
                        // next resolver
                    }
                }
            }
        } catch (e: Exception) {
            logd("DNS: direct resolve failed: ${e.message}")
        }
        return null
    }

    /**
     * BitTorrent over UDP: DHT (a bencoded dictionary), the UDP tracker connect
     * magic, or a uTP header (version 1, a known type, a known extension).
     */
    private fun looksLikeBitTorrentUdp(p: ByteArray): Boolean {
        if (p.size >= 3 && p[0] == 'd'.code.toByte() && p[1] == '1'.code.toByte() && p[2] == ':'.code.toByte()) return true
        if (p.size >= 16 && p[0].toInt() == 0 && p[1].toInt() == 0 && p[2].toInt() == 0x04 &&
            p[3].toInt() == 0x17 && p[4].toInt() == 0x27 && p[5].toInt() == 0x10 &&
            p[6].toInt() == 0x19 && (p[7].toInt() and 0xFF) == 0x80
        ) return true
        if (p.size >= 20) {
            val b0 = p[0].toInt() and 0xFF
            if (b0 and 0x0F == 1 && (b0 shr 4) <= 4 && (p[1].toInt() and 0xFF) <= 2) return true
        }
        return false
    }

    /**
     * Direct UDP for one FWD_UDP session: datagrams out through an unconnected
     * socket outside the VPN, replies framed back to hev with their source as
     * the address, the way the protocol expects.
     */
    private class UdpDirectRelay(private val output: OutputStream) {
        private val socket = DatagramSocket()

        init {
            Thread({
                val buf = ByteArray(65535)
                try {
                    while (!socket.isClosed) {
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
                        val src = packet.address.address
                        val port = packet.port
                        val addr = ByteArray(1 + src.size + 2)
                        addr[0] = if (src.size == 4) 0x01 else 0x04
                        System.arraycopy(src, 0, addr, 1, src.size)
                        addr[addr.size - 2] = (port shr 8).toByte()
                        addr[addr.size - 1] = port.toByte()
                        val len = packet.length
                        synchronized(output) {
                            output.write(byteArrayOf((len shr 8).toByte(), len.toByte(), (3 + addr.size).toByte()))
                            output.write(addr)
                            output.write(buf, 0, len)
                            output.flush()
                        }
                    }
                } catch (_: Exception) {
                    // socket closed or the session went away
                } finally {
                    socket.close()
                }
            }, "tor-bridge-udp-direct").apply { isDaemon = true; start() }
        }

        fun send(ip: ByteArray, port: Int, payload: ByteArray) {
            socket.send(DatagramPacket(payload, payload.size, InetAddress.getByAddress(ip), port))
        }

        fun close() = socket.close()
    }

    // --- DNS cache ---

    /**
     * Cache key: hex of DNS query bytes after the 2-byte transaction ID.
     * This way the same query with different TXIDs hits the cache.
     */
    private fun dnsCacheKey(query: ByteArray): String {
        if (query.size <= 2) return ""
        val out = CharArray((query.size - 2) * 2)
        for (i in 2 until query.size) {
            val v = query[i].toInt() and 0xFF
            out[(i - 2) * 2] = HEX[v ushr 4]
            out[(i - 2) * 2 + 1] = HEX[v and 0x0F]
        }
        return String(out)
    }

    private val HEX = "0123456789abcdef".toCharArray()

    private fun getCachedDns(query: ByteArray): ByteArray? {
        val key = dnsCacheKey(query)
        if (key.isEmpty()) return null
        val entry = dnsCache[key] ?: return null
        if (System.currentTimeMillis() > entry.expiresAt) {
            dnsCache.remove(key)
            return null
        }
        // Copy cached response and replace transaction ID with query's
        val response = entry.response.copyOf()
        if (response.size >= 2 && query.size >= 2) {
            response[0] = query[0]
            response[1] = query[1]
        }
        return response
    }

    private fun cacheDnsResponse(query: ByteArray, response: ByteArray) {
        val key = dnsCacheKey(query)
        if (key.isEmpty()) return
        dnsCache[key] = DnsCacheEntry(response.copyOf(), System.currentTimeMillis() + DNS_CACHE_TTL_MS)
        // Evict old entries periodically (simple: if cache gets large)
        if (dnsCache.size > 500) {
            val now = System.currentTimeMillis()
            dnsCache.entries.removeIf { now > it.value.expiresAt }
        }
    }

    // --- DNS-over-TCP via Tor SOCKS5 ---

    /**
     * Resolvers tried in order, all of them reached over Tor. One being slow,
     * blocked at the exit or simply broken should not take name resolution down
     * with it.
     */
    private val DNS_FALLBACK_RESOLVERS = listOf(
        byteArrayOf(8, 8, 8, 8),   // Google
        byteArrayOf(1, 1, 1, 1),   // Cloudflare
        byteArrayOf(9, 9, 9, 9)    // Quad9
    )

    /**
     * Resolve over Tor: A and AAAA through Tor's DNSPort (one round trip to the
     * exit), everything else -- and anything the DNSPort fails on -- as
     * DNS-over-TCP to public resolvers through a SOCKS stream.
     */
    private fun resolveThroughTor(payload: ByteArray): ByteArray? {
        val qtype = dnsQuestionType(payload)
        // Onion names are only mapped to IPv4 placeholders; an AAAA answer
        // would be a link-local fake that never reaches the tunnel, so say
        // "no IPv6 for this name" and the app uses the IPv4 one.
        if (qtype == 28 && dnsQuestionName(payload)?.lowercase()?.trimEnd('.')?.endsWith(".onion") == true) {
            return dnsNoData(payload)
        }
        if (qtype == 1 || qtype == 28) {
            resolveViaDnsPort(payload)?.let { return it }
        }
        return resolveViaResolvers(payload)
    }

    /**
     * Tor's DNSPort over loopback UDP. Tor answers SERVFAIL when the exit could
     * not resolve the name; that is passed on as is, since asking a public
     * resolver through the same Tor would mostly fail the same way, only slower.
     */
    private fun resolveViaDnsPort(payload: ByteArray): ByteArray? {
        val port = torDnsPort
        if (port <= 0) return null
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = DNS_PORT_TIMEOUT_MS
                socket.send(DatagramPacket(payload, payload.size, InetAddress.getByAddress(LOOPBACK), port))
                val buf = ByteArray(4096)
                val packet = DatagramPacket(buf, buf.size)
                socket.receive(packet)
                if (packet.length >= 12 && buf[0] == payload[0] && buf[1] == payload[1]) {
                    logd("DNS: resolved via Tor DNSPort")
                    buf.copyOf(packet.length)
                } else null
            }
        } catch (e: Exception) {
            logd("DNS: Tor DNSPort gave no answer (${e.message}), falling back")
            null
        }
    }

    /** Ask each resolver in turn over Tor; null when none answers. */
    private fun resolveViaResolvers(payload: ByteArray): ByteArray? {
        for (resolver in DNS_FALLBACK_RESOLVERS) {
            val response = forwardDnsTcp(resolver, payload)
            if (response != null) return response
        }
        Log.w(TAG, "DNS: no resolver answered over Tor")
        return null
    }

    /**
     * Forward DNS query as DNS-over-TCP through Tor's SOCKS5 CONNECT to
     * [resolver]:53. Each call opens a new SOCKS5 connection (no persistent
     * connections to keep it simple).
     */
    private fun forwardDnsTcp(resolver: ByteArray, payload: ByteArray): ByteArray? {
        var socket: Socket? = null
        try {
            // Connect to Tor SOCKS5
            socket = Socket()
            socket.connect(InetSocketAddress(torHost, torSocksPort), DNS_TIMEOUT_MS)
            socket.soTimeout = DNS_TIMEOUT_MS
            socket.tcpNoDelay = true

            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            // SOCKS5 greeting (no auth)
            output.write(byteArrayOf(0x05, 0x01, 0x00))
            output.flush()

            val greetResp = ByteArray(2)
            input.readFully(greetResp)
            if (greetResp[0] != 0x05.toByte()) {
                logd("DNS: Tor SOCKS5 greeting failed")
                return null
            }

            // SOCKS5 CONNECT to the resolver on port 53
            output.write(byteArrayOf(0x05, 0x01, 0x00, 0x01) + resolver + byteArrayOf(0x00, 0x35))
            output.flush()

            // Read CONNECT response
            val connResp = ByteArray(4)
            input.readFully(connResp)
            if (connResp[1] != 0x00.toByte()) {
                logd("DNS: SOCKS5 CONNECT rejected (rep=${connResp[1]})")
                return null
            }

            // Skip remaining response bytes based on address type
            when (connResp[3].toInt() and 0xFF) {
                0x01 -> { val rest = ByteArray(6); input.readFully(rest) }
                0x03 -> { val len = input.read(); val rest = ByteArray(len + 2); input.readFully(rest) }
                0x04 -> { val rest = ByteArray(18); input.readFully(rest) }
            }

            // Send DNS query as TCP (2-byte length prefix per RFC 1035 section 4.2.2)
            output.write(byteArrayOf(
                ((payload.size shr 8) and 0xFF).toByte(),
                (payload.size and 0xFF).toByte()
            ))
            output.write(payload)
            output.flush()

            // Read DNS response (2-byte length prefix)
            val respLenBuf = ByteArray(2)
            input.readFully(respLenBuf)
            val respLen = ((respLenBuf[0].toInt() and 0xFF) shl 8) or (respLenBuf[1].toInt() and 0xFF)

            if (respLen <= 0 || respLen > 65535) {
                logd("DNS: invalid response length: $respLen")
                return null
            }

            val response = ByteArray(respLen)
            input.readFully(response)

            logd("DNS: resolved via Tor (${response.size} bytes)")
            return response
        } catch (e: Exception) {
            logd("DNS-over-TCP failed: ${e.message}")
            return null
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    private fun parseSocksAddress(addrBytes: ByteArray): Pair<String, Int>? {
        if (addrBytes.isEmpty()) return null

        return when (addrBytes[0].toInt() and 0xFF) {
            0x01 -> {
                if (addrBytes.size < 7) return null
                val host = "${addrBytes[1].toInt() and 0xFF}.${addrBytes[2].toInt() and 0xFF}.${addrBytes[3].toInt() and 0xFF}.${addrBytes[4].toInt() and 0xFF}"
                val port = ((addrBytes[5].toInt() and 0xFF) shl 8) or (addrBytes[6].toInt() and 0xFF)
                Pair(host, port)
            }
            0x03 -> {
                val len = addrBytes[1].toInt() and 0xFF
                if (addrBytes.size < 2 + len + 2) return null
                val host = String(addrBytes, 2, len)
                val port = ((addrBytes[2 + len].toInt() and 0xFF) shl 8) or (addrBytes[3 + len].toInt() and 0xFF)
                Pair(host, port)
            }
            0x04 -> {
                if (addrBytes.size < 19) return null
                val parts = mutableListOf<String>()
                for (i in 0 until 16 step 2) {
                    val value = ((addrBytes[1 + i].toInt() and 0xFF) shl 8) or (addrBytes[2 + i].toInt() and 0xFF)
                    parts.add(String.format("%x", value))
                }
                val host = parts.joinToString(":")
                val port = ((addrBytes[17].toInt() and 0xFF) shl 8) or (addrBytes[18].toInt() and 0xFF)
                Pair(host, port)
            }
            else -> null
        }
    }

    private fun bridgeDirect(clientInput: InputStream, clientOutput: OutputStream, directSocket: Socket) {
        directSocket.use { remote ->
            remote.tcpNoDelay = true
            val remoteInput = remote.getInputStream()
            val remoteOutput = remote.getOutputStream()

            val t1 = Thread({
                try {
                    copyStream(clientInput, remoteOutput)
                } catch (_: Exception) {
                } finally {
                    try { remoteOutput.close() } catch (_: Exception) {}
                }
            }, "tor-bridge-direct-c2s")
            t1.isDaemon = true
            t1.start()

            try {
                copyStream(remoteInput, clientOutput)
            } catch (_: Exception) {
            } finally {
                try { remote.close() } catch (_: Exception) {}
                t1.interrupt()
            }
        }
    }

    /**
     * Pump [input] into [output] until EOF. A socket stream is unbuffered, so
     * each read goes out as one write; a BufferedOutputStream in between only
     * copied every byte a second time before flushing it right away.
     */
    private fun copyStream(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        while (!Thread.currentThread().isInterrupted) {
            val bytesRead = input.read(buffer)
            if (bytesRead == -1) break
            output.write(buffer, 0, bytesRead)
        }
        output.flush()
    }

    private fun InputStream.readFully(buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = this.read(buffer, offset, buffer.size - offset)
            if (bytesRead == -1) throw java.io.IOException("Unexpected end of stream")
            offset += bytesRead
        }
    }

    private fun formatIpv6(addr: ByteArray): String {
        val parts = mutableListOf<String>()
        for (i in 0 until 16 step 2) {
            val value = ((addr[i].toInt() and 0xFF) shl 8) or (addr[i + 1].toInt() and 0xFF)
            parts.add(String.format("%x", value))
        }
        return parts.joinToString(":")
    }
}
