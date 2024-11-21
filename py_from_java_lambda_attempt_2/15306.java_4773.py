Here is a translation of the Java code into equivalent Python code:

```Python
import logging
from android.runnable import Runnable
from androidx.annotation import Nullable
from org.bitcoinj.core import Address
from org.slf4j import LoggerFactory

class WalletAddressFragment:
    def __init__(self):
        self.activity = None
        self.fragment_manager = None
        self.nfc_adapter = None
        self.current_address_qr_view = None
        self.current_address_qr_card_view = None
        self.activity_view_model = None
        self.viewModel = None

    @property
    def log(self):
        return logging.getLogger(__name__)

    def on_attach(self, context):
        super().onAttach(context)
        self.activity = context
        self.nfc_adapter = NfcAdapter.getDefaultAdapter(self.activity)

    def on_create(self, savedInstanceState):
        super().onCreate(savedInstanceState)
        self.fragment_manager = self.get_child_fragment_manager()

        self.activity_view_model = ViewModelProvider(self.activity).get(WalletActivityViewModel())
        self.viewModel = ViewModelProvider(self).get(WalletAddressViewModel())

        self.viewModel.qr_code.observe(self, lambda qr_code: 
            current_address_qr_view.set_image_drawable(BitmapDrawable(qr_code))
            current_address_qr_card_view.setOnClickListener(lambda v: self.viewModel.show_wallet_address_dialog.value = Event.simple())
        )

        self.viewModel.bitcoin_uri.observe(self, lambda bitcoin_uri:
            if self.nfc_adapter is not None and bitcoin_uri is not None:
                self.nfc_adapter.set_ndef_push_message(create_ndef_message(bitcoin_uri), self.activity)
            self.activity_view_model.address_loading_finished()
        )

    def on_create_view(self):
        view = LayoutInflater.from(self.activity).inflate(R.layout.wallet_address_fragment, None)

        current_address_qr_view = view.findViewById(R.id.bitcoin_address_qr)
        current_address_qr_card_view = view.findViewById(R.id.bitcoin_address_qr_card)
        current_address_qr_card_view.set_prevent_corner_overlap(False)
        current_address_qr_card_view.set_use_compat_padding(False)
        current_address_qr_card_view.set_max_card_elevation(0)

    def create_ndef_message(self, uri):
        if uri is not None:
            return NdefMessage([NdefRecord.create_uri(uri)])
        else:
            return None

class WalletActivityViewModel:

    pass

class WalletAddressViewModel:

    pass
```

Please note that Python does not have direct equivalent of Java's Android-specific classes and methods. The above code uses a hypothetical `android` module for demonstration purposes only, as there is no real equivalent in standard Python.