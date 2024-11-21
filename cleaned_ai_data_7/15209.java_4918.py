import logging
from datetime import timedelta
from threading import Thread
from queue import Queue
from android.bluetooth import BluetoothAdapter
from android.content import BroadcastReceiver, IntentFilter
from android.os import Handler, IBinder, PowerManager, WakeLock
from androidx.core.app import NotificationCompat
from de.schildbach.wallet import Constants, WalletApplication

class AcceptBluetoothService:
    def __init__(self):
        self.application = None
        self.wallet = None
        self.wake_lock = None
        self.classic_thread = None
        self.payment_protocol_thread = None
        self.service_created_at = 0
        self.handler = Handler()
        self.timeout_ms = timedelta(minutes=5).total_seconds() * 1000

    def onBind(self, intent):
        return None

    def onStartCommand(self, intent, flags, start_id):
        self.handler.removeCallbacks(self.timeoutRunnable)
        self.handler.postDelayed(self.timeoutRunnable, self.timeout_ms)

        return START_NOT_STICKY

    def onCreate(self):
        self.service_created_at = int(time.time())
        logging.debug('.onCreate()')

        super.onCreate()
        self.application = WalletApplication(self.get_application())
        bluetooth_adapter = BluetoothAdapter.getDefaultAdapter()
        power_manager = self.getSystemService(Context.POWER_SERVICE)

        wake_lock = power_manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, self.__class__.__name__)
        wake_lock.acquire()

        notification = NotificationCompat.Builder(self,
            Constants.NOTIFICATION_CHANNEL_ID_ONGOING)
        notification.setSmallIcon(R.drawable.stat_notify_bluetooth_24dp)
        notification.setContentTitle(self.getString(R.string.notification_bluetooth_service_listening))
        notification.setWhen(int(time.time()))
        notification.setOngoing(True)
        notification.setPriority(NotificationCompat.PRIORITY_LOW)

        self.startForeground(Constants.NOTIFICATION_ID_BLUETOOTH, notification.build())

        receiver = BroadcastReceiver()
        intent_filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        self.registerReceiver(receiver, intent_filter)

    def onDestroy(self):
        if self.payment_protocol_thread:
            self.payment_protocol_thread.stop_accepting()

        if self.classic_thread:
            self.classic_thread.stop_accepting()

        self.unregisterReceiver(receiver)
        wake_lock.release()
        self.handler.removeCallbacksAndMessages(None)

        super.onDestroy()

        logging.info('service was up for {} minutes'.format((int(time.time()) - self.service_created_at) / 1000 / 60))

    def handle_tx(self, tx):
        logging.info('tx {} arrived via bluetooth'.format(tx.getTxId()))

        wallet = self.wallet.get_value()
        try:
            if wallet.is_transaction_relevant(tx):
                wallet.receive_pending(tx, None)
                blockchain_service = BlockchainServiceLiveData(self)
                blockchain_service.observe(self,
                    lambda x: blockchain_service.broadcast_transaction(tx))
            else:
                logging.info('tx {} irrelevant'.format(tx.getTxId()))

            return True
        except VerificationException as e:
            logging.info('cannot verify tx {}'.format(tx.getTxId()), e)

    def onReceive(self, context, intent):
        state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, 0)
        if state == BluetoothAdapter.STATE_TURNING_OFF or state == BluetoothAdapter.STATE_OFF:
            logging.info('bluetooth was turned off, stopping service')
            self.stop_self()

    def timeoutRunnable(self):
        logging.info('timeout expired, stopping service')
        self.stop_self()
