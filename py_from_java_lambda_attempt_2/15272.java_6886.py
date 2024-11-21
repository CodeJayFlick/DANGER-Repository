Here is the translation of the given Java code into Python:

```Python
import asyncio
from bitcoinj.core import Address, Coin, ScriptType
from bitcoinj.protocols.payments import PaymentProtocol
from bitcoinj.script import Script
from bitcoinj.uri import BitcoinURI
from typing import Optional

class RequestCoinsViewModel:
    def __init__(self):
        self.application = None  # Replace with your application instance
        self.fresh_receive_address = FreshReceiveAddressLiveData(self.application)
        self.own_name = ConfigOwnNameLiveData(self.application)
        self.exchange_rate = SelectedExchangeRateLiveData(self.application)
        self.amount = asyncio.Semaphore(0)  # Replace with MutableLiveData<Coin>
        self.bluetooth_mac = asyncio.Semaphore(0)  # Replace with MutableLiveData<String>
        self.qr_code = asyncio.Queue()  # Replace with MediatorLiveData<Bitmap>
        self.payment_request = asyncio.Queue()  # Replace with MediatorLiveData<byte[]>
        self.bitcoin_uri = asyncio.Queue()  # Replace with MediatorLiveData<Uri>

    async def maybe_generate_qr_code(self):
        address = await self.fresh_receive_address.get_value()
        if address is not None:
            qr_code.put_nowait(QRCode().bitmap(uri(address, amount=self.amount.get_value(), own_name=self.own_name.get_value(), bluetooth_mac=self.bluetooth_mac.get_value())))

    async def maybe_generate_payment_request(self):
        address = await self.fresh_receive_address.get_value()
        if address is not None:
            payment_url = "bt:" + str(await self.bluetooth_mac.get_value()) if (await self.bluetooth_mac.get_value()) else None
            payment_request.put_nowait(PaymentProtocol.create_payment_request(Constants.NETWORK_PARAMETERS, amount=self.amount.get_value(), address=address, own_name=self.own_name.get_value(), payment_url=payment_url, null).build().to_bytes())

    async def maybe_generate_bitcoin_uri(self):
        address = await self.fresh_receive_address.get_value()
        if address is not None:
            bitcoin_uri.put_nowait(Uri.parse(uri(address, amount=self.amount.get_value(), own_name=self.own_name.get_value(), bluetooth_mac=None)))

    def uri(self, address: Address, amount: Coin, label: str, bluetooth_mac: str) -> str:
        uri = BitcoinURI.convert_to_bitcoin_uri(address, amount, label, None)
        if bluetooth_mac is not None:
            uri += '&' + Bluetooth.MAC_URI_PARAM + '=' + bluetooth_mac
        return uri

class FreshReceiveAddressLiveData:
    def __init__(self):
        self.application = None  # Replace with your application instance
        self.output_script_type = None

    async def get_value(self) -> Address:
        pass  # Implement the logic to retrieve the value from the wallet

    async def on_wallet_active(self, wallet: Wallet):
        await maybe_load()

    async def maybe_load(self):
        if not hasattr(self, 'value'):
            wallet = self.get_wallet()
            output_script_type = self.output_script_type
            asyncio.create_task(lambda: post_value(output_script_type is not None and wallet.fresh_receive_address(output_script_type) or wallet.fresh_receive_address()))

class QRCode:
    def bitmap(self):
        pass  # Implement the logic to generate a QR code

```

Please note that this translation does not include all Java classes (like `AndroidViewModel`, `MutableLiveData`, etc.) as they do not have direct Python equivalents.