import logging
from datetime import timedelta
from moshi import Moshi
from coin_gecko import CoinGecko
from exchange_rate_database import ExchangeRatesDatabase
from exchange_rate_dao import ExchangeRateDao

class ExchangeRatesRepository:
    _instance = None
    UPDATE_FREQ_MS = 10 * timedelta(minutes=1).total_seconds()
    logger = logging.getLogger(__name__)

    def __init__(self, application):
        self.application = application
        self.config = application.get_configuration()
        self.user_agent = f"{application.package_info().version_name} {WalletApplication.http_user_agent}"
        self.db = ExchangeRatesDatabase.get_database(application)
        self.dao = self.db.exchange_rate_dao()

    @classmethod
    def get(cls, application):
        if cls._instance is None:
            cls._instance = cls(application)
        return cls._instance

    def exchange_rate_dao(self):
        self.maybe_request_exchange_rates()
        return self.dao

    def exchange_rate_invalidation_tracker(self):
        return self.db.get_invalidation_tracker()

    def maybe_request_exchange_rates(self):
        if not self.config.enable_exchange_rates:
            return
        now = int(time.time())
        last_updated = self.last_updated.get()
        if last_updated and now - last_updated <= self.UPDATE_FREQ_MS:
            return

        coin_gecko = CoinGecko(Moshi().build())
        request_url = coin_gecko.url()
        headers = {"User-Agent": self.user_agent, "Accept": str(coin_gecko.media_type)}
        response = requests.get(request_url, headers=headers)

        if response.status_code == 200:
            for exchange_rate in coin_gecko.parse(response.content):
                self.dao.insert_or_update(exchange_rate)
            self.last_updated.set(now)
            logging.info(f"Fetched exchange rates from {coin_gecko.url()} (took {response.elapsed.total_seconds():.2f} seconds)")
        else:
            logging.warn(f"HTTP status {response.status_code} {response.reason} when fetching exchange rates from {coin_gecko.url()}")
