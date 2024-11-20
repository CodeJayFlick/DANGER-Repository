import asyncio
from typing import List, Set, Dict, Tuple

class WalletTransactionsViewModel:
    def __init__(self):
        self.application = None  # type: Application
        self.transactions = TransactionsLiveData(self)
        self.wallet = WalletLiveData(self)
        self.transactions_confidence = TransactionsConfidenceLiveData(self)
        self.address_book = AddressBookDatabase.get_database().get_address_book()
        self.config_format = ConfigFormatLiveData(self)

    def set_direction(self, direction):
        self.direction.value = direction

    def set_warning(self, warning):
        self.warning.value = warning

    async def maybe_post_list(self):
        await asyncio.create_task(
            lambda: org.bitcoinj.core.Context.propagate(Constants.CONTEXT)
            and (
                transactions := self.transactions.get_value(),
                format := self.config_format.get_value(),
                address_book := AddressBookEntry.as_map(self.address_book),
                if (transactions is not None
                    and format is not None
                    and address_book is not None):
                    filtered_transactions = []
                    wallet = self.application.get_wallet()
                    direction = self.direction.value
                    for tx in transactions:
                        sent = tx.get_value(wallet).signum() < 0
                        internal = tx.get_purpose() == Purpose.KEY_ROTATION
                        if (direction == Direction.RECEIVED and not sent and not internal) or (
                            direction is None or (direction == Direction.SENT and sent and not internal)):
                            filtered_transactions.append(tx)
                    sorted(filtered_transactions, key=lambda x: TRANSACTION_COMPARATOR(x))
                    self.list.post_value(
                        TransactionsAdapter.build_list_items(self.application,
                                                             filtered_transactions,
                                                             warning.value,
                                                             wallet,
                                                             address_book,
                                                             format,
                                                             self.application.max_connected_peers())
                    )
        )

    @staticmethod
    def transaction_comparator(tx1, tx2):
        pending1 = tx1.get_confidence().get_confidence_type() == ConfidenceType.PENDING
        pending2 = tx2.get_confidence().get_confidence_type() == ConfidenceType.PENDING
        if (pending1 != pending2):
            return -1 if pending1 else 1

        time1 = tx1.get_update_time().time if tx1.get_update_time() is not None else 0
        time2 = tx2.get_update_time().time if tx2.get_update_time() is not None else 0
        if (time1 != time2):
            return -1 if time1 > time2 else 1

        return tx1.get_tx_id().compare(tx2.get_tx_id())

class TransactionsLiveData:
    def __init__(self, application: WalletApplication):
        self.application = application
        self.value = set()

    async def on_wallet_active(self, wallet: Wallet):
        await asyncio.create_task(
            lambda: (
                add_wallet_listener(wallet),
                load()
            )
        )

    async def on_wallet_inactive(self, wallet: Wallet):
        await asyncio.create_task(
            lambda: remove_wallet_listener(wallet)
        )

    def add_wallet_listener(self, wallet: Wallet):
        wallet.add_coins_received_event_listener(self.wallet_listener)
        wallet.add_coins_sent_event_listener(self.wallet_listener)
        wallet.add_reorganize_event_listener(self.wallet_listener)
        wallet.add_change_event_listener(self.wallet_listener)

    def remove_wallet_listener(self, wallet: Wallet):
        wallet.remove_change_event_listener(self.wallet_listener)
        wallet.remove_reorganize_event_listener(self.wallet_listener)
        wallet.remove_coins_sent_event_listener(self.wallet_listener)
        wallet.remove_coins_received_event_listener(self.wallet_listener)

    async def load(self):
        await asyncio.create_task(
            lambda: (
                post_value(get_wallet().get_transactions(True))
            )
        )

class TransactionsConfidenceLiveData:
    def __init__(self, application: WalletApplication):
        self.application = application
        self.value = None

    async def on_wallet_active(self, wallet: Wallet):
        await asyncio.create_task(
            lambda: (
                add_transaction_confidence_event_listener(wallet)
            )
        )

    async def on_wallet_inactive(self, wallet: Wallet):
        await asyncio.create_task(
            lambda: remove_transaction_confidence_event_listener()
        )

    async def on_transaction_confidence_changed(self, wallet: Wallet, tx: Transaction):
        await asyncio.create_task(
            lambda: trigger_load()
        )

    async def load(self):
        await asyncio.create_task(
            lambda: post_value(None)
        )
