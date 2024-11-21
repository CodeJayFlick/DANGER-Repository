import asyncio
from typing import List, Optional

class MaybeMaintenanceViewModel:
    def __init__(self, application: 'WalletApplication'):
        self.application = application
        self.wallet_maintenance_recommended = WalletMaintenanceRecommendedLiveData(application)
        self.show_dialog = MediatorLiveData()
        self.dialog_was_shown = False

    async def maybe_show_dialog(self):
        blockchain_state = await self.application.blockchain_state.get()
        maintenance_recommended = self.wallet_maintenance_recommended.get_value()
        if blockchain_state is not None and not blockchain_state.replaying and maintenance_recommended:
            self.show_dialog.post(None)

    def set_dialog_was_shown(self):
        self.dialog_was_shown = True

    def get_dialog_was_shown(self) -> bool:
        return self.dialog_was_shown


class WalletMaintenanceRecommendedLiveData:
    def __init__(self, application: 'WalletApplication'):
        super().__init__()
        self.application = application

    async def on_wallet_active(self):
        await self.load()

    async def load(self):
        wallet = self.get_wallet()
        try:
            result = await asyncio.create_task(wallet.do_maintenance(None, False))
            if not result:
                post_value(True)
            else:
                post_value(not bool(result))
        except DeterministicUpgradeRequiresPassword as e:
            post_value(True)
        except Exception as e:
            raise RuntimeError(e)


class MediatorLiveData:
    def __init__(self):
        self._data = None

    async def get(self) -> Optional[object]:
        return self._data

    def post(self, value: object):
        self._data = value


class WalletApplication:
    pass
