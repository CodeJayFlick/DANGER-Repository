import threading
from typing import TypeVar, Generic

T = TypeVar('T')

class AbstractWalletLiveData(Generic[T]):
    def __init__(self, application: 'WalletApplication'):
        self.application = application
        self.handler = threading.Thread(target=self.load_wallet)
        self.wallet = None

    def load_wallet(self):
        self.application.get_wallet_async(on_wallet_loaded_listener)

    @property
    def wallet(self) -> T:
        return self._wallet

    @wallet.setter
    def wallet(self, value: T):
        self._wallet = value

    def on_active(self):
        self.application.wallet_changed.observe_forever(self)
        self.load_wallet()

    def on_inactive(self):
        if self.wallet is not None:
            self.on_wallet_inactive(self.wallet)
        self.application.wallet_changed.remove_observer(self)

    @property
    def throttle_ms(self) -> int:
        return 0

    def onChanged(self, v: 'Event[Void]'):
        if self.wallet is not None:
            self.on_wallet_inactive(self.wallet)
        self.load_wallet()

    def on_wallet_active(self, wallet: T):
        pass

    def on_wallet_inactive(self, wallet: T):
        # do nothing by default
        pass


class Event(Generic[T]):
    def __init__(self, value: T):
        self.value = value


class WalletApplication:
    def get_wallet_async(self, callback):
        pass

    @property
    def wallet_changed(self) -> 'Event[Void]':
        return None
