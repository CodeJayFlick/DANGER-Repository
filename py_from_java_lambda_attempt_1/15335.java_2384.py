Here is the translation of the Java code into Python:

```Python
import logging
from typing import Optional

class WalletBalanceWidgetProvider:
    STRIKE_THRU_SPAN = StrikeThroughSpan()

    def __init__(self):
        self.log = logging.getLogger(__name__)

    def onUpdate(self, context: object, app_widget_manager: object, app_widget_ids: list) -> None:
        result = go_async()
        AsyncTask.execute(lambda: 
            application = WalletApplication(context.getApplicationContext())
            balance = application.wallet.balance(BalanceType.estimated)
            config = application.configuration
            exchange_rates_repository = ExchangeRatesRepository(application)
            exchange_rate = config.is_enable_exchange_rates() and \
                exchange_rates_repository.exchange_rate_dao().find_by_currency_code(config.exchange_currency_code) or None
            self.update_widgets(context, app_widget_manager, app_widget_ids, balance, exchange_rate if exchange_rate else None)
            result.finish())

    def onAppWidgetOptionsChanged(self, context: object, app_widget_manager: object, 
                                  app_widget_id: int, new_options: dict) -> None:
        if new_options is not None:
            self.log.info("app widget {} options changed: minWidth={}", app_widget_id,
                          new_options.get(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH))
        result = go_async()
        AsyncTask.execute(lambda: 
            application = WalletApplication(context.getApplicationContext())
            balance = application.wallet.balance(BalanceType.estimated)
            config = application.configuration
            exchange_rates_repository = ExchangeRatesRepository(application)
            exchange_rate = config.is_enable_exchange_rates() and \
                exchange_rates_repository.exchange_rate_dao().find_by_currency_code(config.exchange_currency_code) or None
            self.update_widget(context, app_widget_manager, app_widget_id, new_options, balance, 
                                exchange_rate if exchange_rate else None)
            result.finish())

    @staticmethod
    def update_widgets(context: object, balance: Optional[Coin], exchange_rate: Optional[ExchangeRate]) -> None:
        app_widget_manager = AppWidgetManager.getInstance(context)
        provider_name = ComponentName(context.getPackageName(), WalletBalanceWidgetProvider)

        try:
            app_widget_ids = app_widget_manager.getAppWidgetIds(provider_name)
            if len(app_widget_ids) > 0:
                WalletBalanceWidgetProvider.update_widgets(context, app_widget_manager, 
                                                            app_widget_ids, balance, exchange_rate)
        except RuntimeException as x: # system server dead?
            self.log.warn("cannot update app widgets", x)

    @staticmethod
    def update_widgets(context: object, app_widget_manager: object, app_widget_ids: list, 
                       balance: Optional[Coin], exchange_rate: Optional[ExchangeRate]) -> None:
        for app_widget_id in app_widget_ids:
            options = getAppWidgetOptions(app_widget_manager, app_widget_id)
            WalletBalanceWidgetProvider.update_widget(context, app_widget_manager, 
                                                       app_widget_id, options, balance, exchange_rate)

    @staticmethod
    def update_widget(context: object, app_widget_manager: object, app_widget_id: int, 
                      app_widget_options: dict, balance: Optional[Coin], local_balance_str: str) -> None:
        application = WalletApplication(context.getApplicationContext())
        config = application.configuration
        btc_format = config.format

        if exchange_rate is not None:
            local_balance = exchange_rate.coin_to_fiat(balance)
            local_format = Constants.LOCAL_FORMAT.code(0, 
                Constants.PREFIX_ALMOST_EQUAL_TO + GenericUtils.currency_symbol(exchange_rate.fiat.currency_code))
            prefix_spans = [MonetarySpannable.SMALLER_SPAN, 
                            ForegroundColorSpan(context.getColor(R.color.fg_insignificant_darkdefault))]
            local_balance_str = MonetarySpannable(btc_format, local_balance).apply_markup(prefix_spans, 
                MonetarySpannable.STANDARD_INSIGNIFICANT_SPANS)
            if not Constants.NETWORK_PARAMETERS.getId().equals(NetworkParameters.ID_MAINNET):
                local_balance_str.set_span(WalletBalanceWidgetProvider.STRIKE_THRU_SPAN, 0, 
                    len(local_balance_str), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

        views = RemoteViews(context.getPackageName(), R.layout.wallet_balance_widget_content)
        
        if MonetaryFormat.CODE_BTC.equals(currency_code):
            views.setImageViewResource(R.id.widget_wallet_prefix, R.drawable.currency_symbol_btc)
        elif MonetaryFormat.CODE_MBTC.equals(currency_code):
            views.setImageViewResource(R.id.widget_wallet_prefix, R.drawable.currency_symbol_mbt
                c)
        else:
            views.setImageViewResource(R.id.widget_wallet_prefix, R.drawable.currency_symbol_ubt

    @staticmethod
    def getAppWidgetOptions(app_widget_manager: object, app_widget_id: int) -> dict:
        try:
            method = AppWidgetManager.getMethod("getAppWidgetOptions", Integer.TYPE)
            return method.invoke(app_widget_manager, app_widget_id)
        except Exception as x:
            return None

class StrikeThroughSpan:
    pass
```

Please note that this is a direct translation of the Java code into Python.