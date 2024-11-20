import logging
from datetime import timedelta
from androidhelper import NotificationManager, Intent, PendingIntent, BroadcastReceiver, Context

class BootstrapReceiver(BroadcastReceiver):
    def __init__(self):
        self.log = logging.getLogger(__name__)

    @staticmethod
    def ACTION_DISMISS():
        return "de.schildbach.wallet.dismiss"

    @staticmethod
    def ACTION_DISMISS_FOREVER():
        return "de.schildbach.wallet.dismiss_forever"

    @staticmethod
    def ACTION_DONATE():
        return "de.schildbach.wallet.donate"

    def onReceive(self, context: Context, intent: Intent):
        self.log.info(f"got broadcast: {intent}")
        result = goAsync()
        AsyncTask.execute(lambda: 
            org.bitcoinj.core.Context.propagate(Constants.CONTEXT)
            self.onAsyncReceive(context, intent)
            result.finish())

    @staticmethod
    def onAsyncReceive(self, context: Context, intent: Intent):
        application = WalletApplication.get_instance()

        action = intent.getAction()
        boot_completed = action == "android.intent.action.BOOT_COMPLETED"
        package_replaced = action == "com.example.MY_PACKAGE_REPLACED"

        if package_replaced or boot_completed:
            # make sure wallet is upgraded to HD
            if package_replaced:
                maybe_upgrade_wallet(application.get_wallet())

            # make sure there is always a blockchain sync scheduled
            StartBlockchainService.schedule(application, True)

            # if the app hasn't been used for a while and contains coins, maybe show reminder
            maybe_show_inactivity_notification(application)
        elif action == BootstrapReceiver.ACTION_DISMISS:
            dismiss_notification(context)
        elif action == BootstrapReceiver.ACTION_DISMISS_FOREVER:
            dismiss_notification_forever(context, application.get_configuration())
        elif action == BootstrapReceiver.ACTION_DONATE:
            donate(context, application.get_wallet())

    @staticmethod
    def maybe_upgrade_wallet(self, wallet):
        self.log.info("maybe upgrading wallet")

        # Maybe upgrade wallet from basic to deterministic, and maybe upgrade to the latest script type
        if wallet.is_deterministic_upgrade_required(Constants.UPGRADE_OUTPUT_SCRIPT_TYPE) and not wallet.is_encrypted():
            wallet.upgrade_to_deterministic(Constants.UPGRADE_OUTPUT_SCRIPT_TYPE, None)

        # Maybe upgrade wallet to secure chain
        try:
            wallet.do_maintenance(None, False)
        except Exception as e:
            self.log.error("failed doing wallet maintenance", e)

    @staticmethod
    def maybe_show_inactivity_notification(self, application):
        config = application.get_configuration()
        if not config.remind_balance() or not config.has_been_used() or config.last_used_ago <= Constants.LAST_USAGE_THRESHOLD_INACTIVE_MS:
            return

        wallet = application.get_wallet()
        estimated_balance = wallet.balance(Wallet.BalanceType.estimated_spendable)
        if not estimated_balance.is_positive():
            return

        self.log.info("detected balance, showing inactivity notification")

        available_balance = wallet.balance(Wallet.BalanceType.available_spendable)
        can_donate = Constants.DONATION_ADDRESS is not None and not available_balance.is_less_than(Constants.SOME_BALANCE_THRESHOLD)

        btc_format = config.get_format()
        title = application.getString(R.string.notification_inactivity_title)
        text = StringBuilder(application.getString(R.string.notification_inactivity_message, 
            btc_format.format(estimated_balance)))

        if can_donate:
            text.append("\n\n").append(application.getString(R.string.notification_inactivity_message_donate))

        notification = NotificationCompat.Builder(application, Constants.NOTIFICATION_CHANNEL_ID_IMPORTANT)
        notification.set_style(NotificationCompat.BigTextStyle().big_text(text))
        notification.set_color(application.getColor(R.color.fg_network_significant))
        notification.set_small_icon(R.drawable.stat_notify_received_24dp)
        notification.set_content_title(title)
        notification.set_content_text(text)
        notification.set_content_intent(PendingIntent.getActivity(application, 0, Intent(application, WalletActivity), 
            0))

        if not can_donate:
            dismiss_intent = Intent(application, BootstrapReceiver)
            dismiss_intent.setAction(BootstrapReceiver.ACTION_DISMISS)
            notification.add_action(NotificationCompat.Action.Builder(0, application.getString(R.string.notification_inactivity_action_dismiss), 
                PendingIntent.get_broadcast(dismiss_intent, 0)).build())

        dismiss_forever_intent = Intent(application, BootstrapReceiver)
        dismiss_forever_intent.setAction(BootstrapReceiver.ACTION_DISMISS_FOREVER)
        notification.add_action(NotificationCompat.Action.Builder(0, application.getString(R.string.notification_inactivity_action_dismiss_forever), 
            PendingIntent.get_broadcast(dismiss_forever_intent, 0)).build())

        if can_donate:
            donate_intent = Intent(application, BootstrapReceiver)
            donate_intent.setAction(BootstrapReceiver.ACTION_DONATE)
            notification.add_action(NotificationCompat.Action.Builder(0, application.getString(R.string.wallet_options_donate), 
                PendingIntent.get_broadcast(donate_intent, 0)).build())

        nm = NotificationManager(application.getSystemService(Context.NOTIFICATION_SERVICE))
        nm.notify(Constants.NOTIFICATION_ID_INACTIVITY, notification.build())

    @staticmethod
    def dismiss_notification(self, context):
        self.log.info("dismissing inactivity notification")
        nm = NotificationManager(context.getSystemService(Context.NOTIFICATION_SERVICE))
        nm.cancel(Constants.NOTIFICATION_ID_INACTIVITY)

    @staticmethod
    def dismiss_notification_forever(self, context, config):
        self.log.info("dismissing inactivity notification forever")
        config.set_remind_balance(False)
        nm = NotificationManager(context.getSystemService(Context.NOTIFICATION_SERVICE))
        nm.cancel(Constants.NOTIFICATION_ID_INACTIVITY)

    @staticmethod
    def donate(self, context, wallet):
        balance = wallet.balance(Wallet.BalanceType.available_spendable)
        SendCoinsActivity.start_donate(context, balance, FeeCategory.ECONOMIC, 
            Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK)
        nm = NotificationManager(context.getSystemService(Context.NOTIFICATION_SERVICE))
        nm.cancel(Constants.NOTIFICATION_ID_INACTIVITY)
        context.send_broadcast(Intent(ACTION_CLOSE_SYSTEM_DIALOGS))

