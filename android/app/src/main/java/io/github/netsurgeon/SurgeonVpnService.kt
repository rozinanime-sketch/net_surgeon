package io.github.netsurgeon

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService

/**
 * VPN без сервера: весь трафик телефона приходит сюда через TUN и уходит
 * в Rust-ядро, которое само выходит в интернет с техниками обхода.
 *
 * Сервис работает на переднем плане, с уведомлением. Без этого его нельзя
 * запустить, когда экрана приложения не видно: из плитки, при загрузке
 * телефона или системой в режиме «Постоянная VPN».
 */
class SurgeonVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        // Первым делом: после startForegroundService у сервиса есть
        // несколько секунд, иначе система убьёт приложение.
        startForeground(NOTIFICATION_ID, notification())
        launch()
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
                shutdown()
                return
            }

        // Язык ресурсов, а не Locale.getDefault(): так учитывается и язык,
        // выбранный для одного приложения в настройках Android 13+.
        val lang = if (resources.configuration.locales[0].language == "ru") "ru" else "en"
        // detachFd: дескриптор теперь принадлежит ядру, и Java его не закроет
        // из-под него при сборке мусора.
        val error = NativeBridge.start(tun.detachFd(), DataFiles.dir(this).absolutePath, lang)
        if (error != null) {
            shutdown()
            return
        }
        refreshTile(this)
    }

    private fun shutdown() {
        NativeBridge.stop()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        refreshTile(this)
    }

    /** Пользователь выключил VPN в системных настройках или включил другой. */
    override fun onRevoke() {
        shutdown()
    }

    override fun onDestroy() {
        NativeBridge.stop()
        refreshTile(this)
        super.onDestroy()
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        // Важность низкая: уведомление без звука и не всплывает, оно лишь
        // показывает, что обход включён, и даёт его выключить.
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, stopIntent(this), PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_surgeon)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.turn_off), stop).build())
            .build()
    }

    companion object {
        const val ACTION_STOP = "io.github.netsurgeon.STOP"
        private const val MTU = 1500
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1

        fun startIntent(context: Context) = Intent(context, SurgeonVpnService::class.java)

        fun stopIntent(context: Context) = startIntent(context).setAction(ACTION_STOP)

        /** Плитка в шторке перерисуется при следующем показе. */
        fun refreshTile(context: Context) {
            TileService.requestListeningState(
                context, ComponentName(context, SurgeonTileService::class.java)
            )
        }
    }
}
