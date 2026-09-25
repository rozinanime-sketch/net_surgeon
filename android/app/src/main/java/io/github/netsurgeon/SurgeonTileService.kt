package io.github.netsurgeon

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Плитка в шторке уведомлений: включает и выключает обход одним нажатием. */
class SurgeonTileService : TileService() {

    override fun onStartListening() {
        render()
    }

    override fun onClick() {
        if (NativeBridge.isRunning()) {
            startService(SurgeonVpnService.stopIntent(this))
        } else if (VpnService.prepare(this) != null) {
            // Разрешения на VPN ещё нет, а спросить его может только экран
            // приложения: открываем его, он сразу покажет системный запрос.
            openApp()
        } else {
            try {
                startForegroundService(SurgeonVpnService.startIntent(this))
            } catch (e: IllegalStateException) {
                // Некоторые прошивки не дают запускать сервис из плитки.
                openApp()
            }
        }
        render()
    }

    private fun render() {
        val tile = qsTile ?: return
        val running = NativeBridge.isRunning()
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(if (running) R.string.tile_on else R.string.tile_off)
        }
        tile.updateTile()
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_START, true)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
