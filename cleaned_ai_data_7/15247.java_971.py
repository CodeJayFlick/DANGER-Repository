import logging
from typing import List, Optional

class ExchangeRatesViewModel:
    def __init__(self):
        self.application = None  # Replace with actual application instance
        self.exchange_rate_dao = None  # Replace with actual exchange rate DAO instance
        self._exchange_rates_live_data = MediatorLiveData()
        self.underlying_exchange_rate_live_data: Optional[Live] = None
        self.balance = WalletBalanceLiveData(self.application)
        self.is_constrained = False

    @property
    def selected_exchange_rate(self) -> MutableLiveData:
        return MutableLiveData()

    @property
    def initial_exchange_rate(self):
        pass  # Replace with actual event handling logic

    def get_exchange_rates(self) -> LiveData:
        return _exchange_rates_live_data

    def set_constraint(self, constraint: str = None):
        if self.underlying_exchange_rate_live_data is not None:
            self._exchange_rates_live_data.remove_source(self.underlying_exchange_rate_live_data)
        if constraint is not None:
            self.underlying_exchange_rate_live_data = self.exchange_rate_dao.find_by_constraint(constraint.lower())
            self.is_constrained = True
        else:
            self.underlying_exchange_rate_live_data = self.exchange_rate_dao.find_all()
            self.is_constrained = False
        self._exchange_rates_live_data.add_source(self.underlying_exchange_rate_live_data, lambda exchange_rates: self._exchange_rates_live_data.set_value(exchange_rates))

    def is_constrained(self) -> bool:
        return self.is_constrained

    def get_balance(self) -> WalletBalanceLiveData:
        if self.balance is None:
            self.balance = WalletBalanceLiveData(self.application)
        return self.balance
