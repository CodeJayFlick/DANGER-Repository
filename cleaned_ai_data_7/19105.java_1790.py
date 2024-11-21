import sqlite3
from datetime import timedelta

class LocalConnectionProvider:
    def __init__(self):
        self._data_source = None

    @property
    def data_source(self):
        return self._data_source

    @data_source.setter
    def data_source(self, value):
        self._data_source = value

    def initialize(self, config):
        if not self.data_source:
            # configure pool
            initial_size = config.get_pool_initial_size()
            max_size = config.get_pool_max_size()
            min_size = config.get_pool_min_size()
            connection_lifetime_minutes = config.get_pool_connection_lifetime_minutes()
            acquisition_timeout_seconds = config.get_pool_acquisition_timeout_seconds()

            # configure supplier
            jdbc_url = config.get_jdbc_url()
            if config.get_jdbc_user():
                username = config.get_jdbc_user()
                password = config.get_jdbc_pass()
            else:
                username, password = None, None

            transaction_isolation = config.get_pool_transaction_isolation()

            # create data source
            self.data_source = sqlite3.connect(
                jdbc_url,
                isolation_level=transaction_isolation,
                timeout=acquisition_timeout_seconds,
                initial_size=initial_size,
                max_size=max_size,
                min_size=min_size,
                connection_lifetime_minutes=timedelta(minutes=connection_lifetime_minutes)
            )

    def close(self):
        if self.data_source and hasattr(self.data_source, 'close'):
            try:
                self.data_source.close()
            finally:
                self.data_source = None

    def borrow_connection(self) -> sqlite3.Connection:
        return self.data_source
