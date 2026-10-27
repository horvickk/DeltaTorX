package io.deltator

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import io.deltator.util.AppLog as Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/**
 * The Quick Settings tile: one tap connects or disconnects, the subtitle says
 * what the connection is doing.
 *
 * A tap does what the ring on the main screen does, minus the parts that need
 * a screen: when Android still has to ask for VPN permission, the app is
 * opened with a request to connect, since that dialog can only be shown from
 * an activity.
 */
class DeltaTorTileService : TileService() {

    private var scope: CoroutineScope? = null
    private var watch: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        val s = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        scope = s
        watch = s.launch {
            combine(AppState.state, AppState.chainState) { vpn, chain -> view(vpn, chain) }
                .distinctUntilChanged()
                .collect { render(it) }
        }
    }

    override fun onStopListening() {
        watch?.cancel()
        scope?.cancel()
        scope = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        val s = AppState.state.value
        val chain = AppState.chainState.value
        val action = when {
            chain.status == AppState.ChainStatus.CONNECTING ||
                chain.status == AppState.ChainStatus.CONNECTED -> TorVpnService.ACTION_CHAIN_DISCONNECT
            // The cores are being killed; a start now would race the teardown.
            s.stopping -> return
            s.socksEndpoint.isNotEmpty() || s.connecting || s.connected || s.reconnecting ->
                TorVpnService.ACTION_DISCONNECT
            s.torRunning -> TorVpnService.ACTION_START_VPN
            else -> {
                if (!Config.proxyOnlyMode && VpnService.prepare(this) != null) {
                    openAppToConnect()
                    return
                }
                TorVpnService.ACTION_CONNECT
            }
        }
        try {
            ContextCompat.startForegroundService(
                this,
                Intent(this, TorVpnService::class.java).setAction(action)
            )
        } catch (e: Exception) {
            // Some ROMs refuse a foreground start from the shade; the app can
            // always do it.
            Log.w(TAG, "tile could not start the service (${e.message}), opening the app")
            openAppToConnect()
        }
    }

    /** Open the app and have it connect, asking for VPN permission if needed. */
    private fun openAppToConnect() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(MainActivity.EXTRA_CONNECT, true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this, 0, intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private data class View(val state: Int, val subtitle: String)

    private fun view(vpn: AppState.VpnState, chain: AppState.ChainState): View = when {
        chain.status == AppState.ChainStatus.CONNECTED -> View(Tile.STATE_ACTIVE, "Chain on")
        chain.status == AppState.ChainStatus.CONNECTING -> View(Tile.STATE_ACTIVE, "Chain connecting…")
        vpn.stopping -> View(Tile.STATE_INACTIVE, "Stopping…")
        vpn.reconnecting -> View(Tile.STATE_ACTIVE, "Reconnecting…")
        vpn.connected -> View(Tile.STATE_ACTIVE, "Connected")
        vpn.socksEndpoint.isNotEmpty() -> View(Tile.STATE_ACTIVE, "Proxy on")
        vpn.connecting -> View(Tile.STATE_ACTIVE, "Connecting…")
        vpn.torRunning -> View(Tile.STATE_INACTIVE, "Tor on · VPN off")
        else -> View(Tile.STATE_INACTIVE, "Off")
    }

    private fun render(v: View) {
        val tile = qsTile ?: return
        tile.state = v.state
        tile.label = getString(R.string.app_name)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_tor)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = v.subtitle
        }
        tile.contentDescription = "${getString(R.string.app_name)}: ${v.subtitle}"
        tile.updateTile()
    }

    companion object {
        private const val TAG = "Tile"
    }
}
