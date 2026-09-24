package io.github.netsurgeon

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.util.Locale

/**
 * VPN без сервера: весь трафик телефона приходит сюда через TUN и уходит
 * в Rust-ядро, которое само выходит в интернет с техниками обхода.
 */
class SurgeonVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                return START_NOT_STICKY
            }
            else -> launch()
        }
        return START_STICKY
    }

    private fun launch() {
        if (NativeBridge.isRunning()) return
        DataFiles.ensure(this)

        val tun: ParcelFileDescriptor = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(MTU)
            // Адрес самого интерфейса. Ни с чем не должен совпадать, трафика
            // на него нет: tun2proxy разбирает пакеты в своём стеке.
            .addAddress("10.111.222.1", 30)
            .addRoute("0.0.0.0", 0)
            // Запросы на этот адрес уходят в TUN, и на них отвечает virtual
            // DNS в ядре. Сам адрес произвольный, лишь бы попадал в маршрут.
            .addDnsServer("198.18.0.2")
            // Своё приложение — мимо VPN: иначе ядро отправляло бы свои же
            // соединения обратно в себя, и получилась бы петля.
            .addDisallowedApplication(packageName)
            .establish()
            ?: run {
                // null — пользователь отозвал разрешение на VPN.
                stopSelf()
                return
            }

        val lang = if (Locale.getDefault().language == "ru") "ru" else "en"
        // detachFd: дескриптор теперь принадлежит ядру, и Java его не закроет
        // из-под него при сборке мусора.
        val error = NativeBridge.start(tun.detachFd(), DataFiles.dir(this).absolutePath, lang)
        if (error != null) {
            stopSelf()
        }
    }

    private fun shutdown() {
        NativeBridge.stop()
        stopSelf()
    }

    /** Пользователь выключил VPN в системных настройках или включил другой. */
    override fun onRevoke() {
        shutdown()
    }

    override fun onDestroy() {
        NativeBridge.stop()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "io.github.netsurgeon.STOP"
        private const val MTU = 1500
    }
}
