package io.github.netsurgeon

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * Автозапуск после включения телефона, если он включён галочкой на главном
 * экране.
 *
 * Надёжнее системная «Постоянная VPN» (Настройки → VPN → net surgeon):
 * её поднимает сама система, и прошивки, которые режут автозапуск
 * приложений, ей не мешают. Этот приёмник — для тех, кто её не включил.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Prefs.autostart(context)) return
        // Разрешение на VPN могли отозвать, или его забрал другой VPN:
        // спросить заново без экрана нельзя, поэтому молча не запускаемся.
        if (VpnService.prepare(context) != null) return
        context.startForegroundService(SurgeonVpnService.startIntent(context))
    }
}
