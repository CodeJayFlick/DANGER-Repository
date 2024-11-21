Here is a translation of the provided Java code into equivalent Python:

```Python
import asyncio
from typing import Any

class WalletBalanceLiveData:
    def __init__(self, application: Any, balance_type: str):
        self.balance_type = balance_type
        self.config = application.get_configuration()
        super().__init__()

    async def load(self) -> None:
        wallet = await get_wallet()
        asyncio.create_task(
            lambda: self.post_value(wallet.get_balance(self.balance_type))
        )

    async def on_wallet_active(self, wallet: Any):
        add_wallet_listener(wallet)
        self.config.register_on_shared_preference_changed_listener(self)
        await self.load()

    async def on_wallet_inactive(self, wallet: Any):
        self.config.unregister_on_shared_preference_changed_listener(self)
        remove_wallet_listener(wallet)

    def trigger_load(self) -> None:
        asyncio.create_task(self.load())

class WalletListener:
    def __init__(self):
        pass

    def on_coins_received(self, wallet: Any, tx: Any, prev_balance: Any, new_balance: Any) -> None:
        self.trigger_load()

    def on_coins_sent(self, wallet: Any, tx: Any, prev_balance: Any, new_balance: Any) -> None:
        self.trigger_load()

    def on_reorganize(self, wallet: Any) -> None:
        self.trigger_load()

    def on_wallet_changed(self, wallet: Any) -> None:
        self.trigger_load()
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python.

Here are some key differences:

1. In the original code, there were several methods marked as `@Override`, which indicates they're overriding methods from parent classes. This concept doesn't exist directly in Python; instead, you can simply define a method with the same name and signature.
2. The Java code used an `AsyncTask` to execute tasks asynchronously. In Python, we use the built-in `asyncio.create_task()` function for this purpose.
3. The original code had several listeners (e.g., `WalletCoinsReceivedEventListener`, etc.) that were implemented using interfaces in Java. In Python, these are simply defined as classes with methods matching those of their respective interfaces.

This translation is not a direct copy-paste from the provided Java code; it's an equivalent implementation written directly in Python.