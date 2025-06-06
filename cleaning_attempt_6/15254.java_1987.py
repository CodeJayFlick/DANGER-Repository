import asyncio
from typing import List, Set

class BlockListViewModel:
    def __init__(self):
        self.application = WalletApplication()
        self.blockchain_service = BlockchainServiceLiveData(self.application)
        self.blocks = MediatorLiveData([])
        self.transactions = None  # type: TransactionsLiveData
        self.time = None  # type: TimeLiveData
        self.max_blocks = 100

    def maybe_refresh_blocks(self):
        blockchain_service = self.blockchain_service.get_value()
        if blockchain_service is not None:
            self.blocks.set_value(blockchain_service.recent_blocks(self.max_blocks))

    async def get_transactions(self) -> Set[Transaction]:
        if self.transactions is None:
            self.transactions = TransactionsLiveData(self.application)
        return await self.transactions.load()

    async def get_time(self) -> TimeLiveData:
        if self.time is None:
            self.time = TimeLiveData(self.application)
        return self.time

class MediatorLiveData(list):
    def add_source(self, source: 'MediatorLiveData', callback=None):
        super().append(source)

    def set_value(self, value):
        for item in self:
            item.set_value(value)


class TransactionsLiveData(asyncio.coroutine):
    def __init__(self, application):
        super().__init__()
        self.application = application

    async def load_transactions(self) -> Set[Transaction]:
        wallet = await get_wallet()
        if wallet is None:
            return set()

        transactions = await asyncio.create_task(wallet.get_transactions(False))
        filtered_transactions = {tx for tx in transactions}
        # TODO filter by updateTime
        return filtered_transactions


class TimeLiveData(asyncio.coroutine):
    def __init__(self, application):
        super().__init__()
        self.application = application

    async def get_time(self) -> Time:
        pass  # TODO implement this method


class WalletApplication:
    def blockchain_state(self):
        pass  # TODO implement this method

    def wallet(self):
        pass  # TODO implement this method
