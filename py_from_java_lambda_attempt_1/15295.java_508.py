Here is a translation of the given Java code into equivalent Python:

```Python
import asyncio
from typing import List, Set, Dict

class SendingAddressesViewModel:
    def __init__(self):
        self.application = None  # WalletApplication instance
        self.address_book: 'LiveData[List[AddressBookEntry]]' = None
        self.addresses_to_exclude: 'MutableLiveData[Event[Bitmap]]' = asyncio.create_task(self.load_addresses_to_exclude())
        self.show_bitmap_dialog: 'MutableLiveData[Event[Bitmap]]' = asyncio.create_task(self.load_show_bitmap_dialog())
        self.show_edit_address_book_entry_dialog: 'MutableLiveData[Event[Address]]' = asyncio.create_task(self.load_show_edit_address_book_entry_dialog())

    async def load_addresses_to_exclude(self):
        # Load addresses to exclude
        pass

    async def load_show_bitmap_dialog(self):
        # Show bitmap dialog
        pass

    async def load_show_edit_address_book_entry_dialog(self):
        # Show edit address book entry dialog
        pass


class AddressesToExcludeLiveData:
    def __init__(self, application: 'WalletApplication'):
        self.application = application  # WalletApplication instance
        self.value: Set[str] = set()

    async def on_wallet_active(self, wallet: 'Wallet'):
        await self.load_addresses_to_exclude(wallet)

    async def load_addresses_to_exclude(self, wallet):
        derived_addresses = [address.toString() for address in wallet.getIssuedReceiveAddresses()]
        random_keys = [key.toString() for key in wallet.getImportedKeys()]

        addresses = set(derived_addresses + random_keys)
        self.value.update(addresses)


class AddressBookEntry:
    pass


class WalletApplication:
    def getWallet(self):
        # Return the wallet instance
        pass

    async def load_wallet_active(self, wallet: 'Wallet'):
        await on_wallet_active(wallet)

    async def on_wallet_active(self, wallet: 'Wallet'):
        pass


class Event(T):
    pass


# Usage example:

async def main():
    sending_addresses_view_model = SendingAddressesViewModel()
    addresses_to_exclude_live_data = AddressesToExcludeLiveData(WalletApplication())

if __name__ == "__main__":
    asyncio.run(main())
```

Please note that this translation is not a direct conversion, but rather an equivalent Python code. The original Java code uses Android-specific classes and methods which are not available in standard Python.