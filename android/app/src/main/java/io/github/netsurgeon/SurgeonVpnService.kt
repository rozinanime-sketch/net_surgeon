package io.github.netsurgeon

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import android.widget.Toast

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

        // detachFd: дескриптор теперь принадлежит ядру, и Java его не закроет
        // из-под него при сборке мусора.
        val error = NativeBridge.start(tun.detachFd(), DataFiles.dir(this).absolutePath, NativeBridge.lang(this))
        if (error != null) {
            // Причину — на экран: иначе обход молча не включался (битый
            // config.toml, занятый порт), и узнать почему можно было только
            // в логе.
            Toast.makeText(this, getString(R.string.start_failed, error), Toast.LENGTH_LONG).show()
            shutdown()
            return
        }
        watchNetwork()
        handler.postDelayed(watchdog, WATCHDOG_MS)
        refreshTile(this)
    }

    private val handler = Handler(Looper.getMainLooper())

    /**
     * Ядро может остановиться и само (упал tun2proxy). Тогда сервис тоже
     * выключается: иначе висело бы уведомление «обход включён», а включить
     * заново было бы нельзя.
     */
    private val watchdog = object : Runnable {
        override fun run() {
            if (!NativeBridge.isRunning()) {
                shutdown()
                return
            }
            handler.postDelayed(this, WATCHDOG_MS)
        }
    }

    /**
     * Смена сети (Wi-Fi ↔ мобильная) меняет число хопов до DPI и серверов,
     * поэтому подобранное под прежнюю сеть состояние ядра надо сбросить —
     * иначе, например, TTL приманки окажется неверным. Соединения не рвём:
     * новые перемеряются сами.
     */
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    /**
     * Отпечаток сети без особых разрешений: интерфейс, шлюз и DNS. Имя
     * Wi-Fi требует разрешения на геолокацию, поэтому его нет. Одного
     * интерфейса с DNS мало: домашний и рабочий Wi-Fi оба давали
     * «wlan0|192.168.1.1», и стратегии одной сети применялись в другой.
     */
    private fun networkId(lp: LinkProperties): String {
        val iface = lp.interfaceName ?: ""
        val gateway = lp.routes.firstOrNull { it.isDefaultRoute && it.hasGateway() }?.gateway?.hostAddress ?: ""
        val dns = lp.dnsServers.mapNotNull { it.hostAddress }.sorted().joinToString(",")
        return "$iface|$gateway|$dns"
    }

    private fun watchNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            // Активно берём свойства при появлении сети: onLinkPropertiesChanged
            // при регистрации приходит не на всех прошивках, а без id стратегии
            // не привязываются к сети.
            override fun onAvailable(network: Network) {
                cm.getLinkProperties(network)?.let { NativeBridge.onNetworkChanged(networkId(it)) }
            }
            // И при смене свойств (новая сеть, другой DNS) — обновляем id.
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                NativeBridge.onNetworkChanged(networkId(lp))
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
        } catch (_: Exception) {
            // Регистрация может не удаться на редких прошивках — не критично.
        }
    }

    private fun unwatchNetwork() {
        val cb = netCallback ?: return
        netCallback = null
        runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
    }

    private fun shutdown() {
        handler.removeCallbacks(watchdog)
        unwatchNetwork()
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
        handler.removeCallbacks(watchdog)
        unwatchNetwork()
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
        private const val WATCHDOG_MS = 2000L

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
