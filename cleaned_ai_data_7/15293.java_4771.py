# Copyright the original author or authors.

import os
from typing import Any

class SendCoinsQrActivity:
    def __init__(self):
        self.wallet_activity_view_model = None  # type: AbstractWalletActivityViewModel

    REQUEST_CODE_SCAN = 0

    def on_create(self, savedInstanceState=None) -> None:
        super().on_create(savedInstanceState)
        if not hasattr(self, 'wallet_activity_view_model'):
            self.wallet_activity_view_model = ViewModelProvider(self).get(AbstractWalletActivityViewModel)

        if savedInstanceState is None:
            ScanActivity.start_for_result(self, REQUEST_CODE_SCAN)

    def on_activity_result(self, requestCode: int, resultCode: int, intent: Any) -> None:
        if requestCode == SendCoinsQrActivity.REQUEST_CODE_SCAN and resultCode == 0:
            input = intent.get('extra', {}).get(ScanActivity.INTENT_EXTRA_RESULT)
            parser = StringInputParser(input)

            def handle_payment_intent(payment_intent):
                SendCoinsActivity.start(self, payment_intent)
                self.finish()

            def handle_private_key(key: Any) -> None:
                if Constants.ENABLE_SWEEP_WALLET:
                    SweepWalletActivity.start(self, key)
                    self.finish()
                else:
                    super().handle_private_key(key)

            def handle_direct_transaction(transaction):
                wallet_activity_view_model.broadcast_transaction(transaction)
                self.finish()

            parser.parse(handle_payment_intent, handle_private_key, handle_direct_transaction)

        elif requestCode == SendCoinsQrActivity.REQUEST_CODE_SCAN and resultCode != 0:
            self.finish()
