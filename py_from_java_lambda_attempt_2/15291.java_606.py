Here is a translation of your Java code into Python:

```Python
class SweepWalletFragment:
    def __init__(self):
        self.activity = None
        self.application = None
        self.config = None
        self.fragment_manager = None
        self.handler = None
        self.background_thread = None
        self.background_handler = None

    @property
    def message_view(self):
        return None

    @property
    def password_view_group(self):
        return None

    @property
    def password_view(self):
        return None

    @property
    def bad_password_view(self):
        return None

    @property
    def balance_view(self):
        return None

    @property
    def hint_view(self):
        return None

    @property
    def sweep_transaction_view(self):
        return None

    @property
    def sweep_transaction_view_holder(self):
        return None

    @property
    def view_go(self):
        return None

    @property
    def view_cancel(self):
        return None

    @property
    def reload_action(self):
        return None

    @property
    def scan_action(self):
        return None

    def on_attach(self, context):
        self.activity = AbstractWalletActivity(context)
        self.application = WalletApplication()
        self.config = Configuration()

    def on_create(self, savedInstanceState):
        super().on_create(savedInstanceState)
        self.fragment_manager = getChildFragmentManager()
        set_has_options_menu(True)

        if not Constants.ENABLE_SWEEP_WALLET:
            raise Exception("ENABLE_SWEEP_WALLET is disabled")

        wallet_activity_view_model = ViewModelProvider(activity).get(AbstractWalletActivityViewModel())
        wallet_activity_view_model.wallet.observe(self, lambda wallet: self.update_view())

    def on_destroy(self):
        background_thread.get_looper().quit()
        super().on_destroy()

    def on_result(self, request_code, result_code, intent):
        if request_code == REQUEST_CODE_SCAN:
            if result_code == Activity.RESULT_OK:
                input = intent.getStringExtra(ScanActivity.INTENT_EXTRA_RESULT)

                new StringInputParser(input) {
                    @Override
                    protected void handle_private_key(private_key_to_sweep):
                        viewModel.private_key_to_sweep.set_value(private_key_to_sweep)
                        maybe_decode_key()

                    @Override
                    protected void handle_payment_intent(payment_intent):
                        cannot_classify(input)

                    @override
                    protected void error(message_res_id, message_args):
                        viewModel.show_dialog.set_value(DialogEvent.dialog(R.string.sweep_wallet_fragment_scan_error_title,
                                                                                       message_res_id, *message_args))
                }.parse()

    def on_createOptionsMenu(self, menu, inflater):
        inflater.inflate(R.menu.sweep_wallet_fragment_options, menu)

        reload_action = menu.find_item(R.id.sweep_wallet_options_reload)
        scan_action = menu.find_item(R.id.sweep_wallet_options_scan)

        if pm.has_system_feature(PackageManager.FEATURE_CAMERA) or pm.has_system_feature(PackageManager.FEATURE_CAMERA_FRONT):
            scan_action.setVisible(True)

    def onOptionsItemSelected(self, item_id):
        if item_id == R.id.sweep_wallet_options_reload:
            handle_reload()
            return True
        elif item_id == R.id.sweep_wallet_options_scan:
            ScanActivity.start_for_result(self, activity, REQUEST_CODE_SCAN)
            return True

    def handle_reload(self):
        if viewModel.wallet_to_sweep.get_value() is None:
            return
        request_wallet_balance()

    def maybe_decode_key_runnable(self):
        maybe_decode_key()

    def maybe_decode_key(self):
        check_state(viewModel.state == SweepWalletViewModel.State.DECODE_KEY)
        private_key_to_sweep = viewModel.private_key_to_sweep.get_value()
        check_state(private_key_to_sweep is not None)

        if isinstance(private_key_to_sweep, DumpedPrivateKey):
            key = ((DumpedPrivateKey)private_key_to_sweep).get_key()
            ask_confirm_sweep(key)
        elif isinstance(private_key_to_sweep, BIP38PrivateKey):
            bad_password_view.set_visible(False)

            password = password_view.get_text().trim()
            if not password.is_empty():
                viewModel.progress.set_value(R.string.sweep_wallet_fragment_decrypt_progress)
                new DecodePrivateKeyTask(background_handler) {
                    @Override
                    protected void on_success(encrypted_key):
                        log.info("successfully decoded BIP38 private key")
                        viewModel.progress.set_value(None)
                        ask_confirm_sweep(encrypted_key)

                    @override
                    protected void on_bad_passphrase():
                        log.info("failed decoding BIP38 private key (bad password)")
                        viewModel.progress.set_value(None)
                        bad_password_view.set_visible(True)
                }.decode_private_key((BIP38PrivateKey)private_key_to_sweep, password)
        else:
            raise Exception(f"cannot handle type: {private_key_to_sweep.__class__.__name__}")

    def ask_confirm_sweep(self, key):
        wallet_to_sweep = Wallet.create_basic(Constants.NETWORK_PARAMETERS)
        wallet_to_sweep.import_key(key)
        viewModel.wallet_to_sweep.set_value(wallet_to_sweep)

        self.state = SweepWalletViewModel.State.CONFIRM_SWEEP

        # delay until fragment is resumed
        handler.post(request_wallet_balance_runnable)

    def request_wallet_balance(self):
        if viewModel.wallet_to_sweep.get_value() is None:
            return
        viewModel.progress.set_value(R.string.sweep_wallet_fragment_request_wallet_balance_progress)
        new RequestWalletBalanceTask(background_handler) {
            @Override
            protected void on_result(set<UTXO> utxos):
                wallet = wallet_activity_view_model.wallet.get_value()
                for transaction in wallet.transactions:
                    if not spent_by(transaction, utxo):
                        sorted_utxos.add(utxo)
                fake_txns = {}
                for utxo in sorted_utxos:
                    tx = fake_txns.get(utxo.hash())
                    if tx is None:
                        tx = FakeTransaction(Constants.NETWORK_PARAMETERS, utxo.hash(), utxo.hash())
                        fake_txns[tx.tx_id] = tx
                    transaction_output = TransactionOutput(Constants.NETWORK_PARAMETERS, tx,
                                                             utxo.value, new byte[] {})
                wallet_to_sweep.clear_transactions(0)
                for tx in fake_txns.values():
                    wallet_to_sweep.add_wallet_transaction(WalletTransaction.Pool.UNSPENT, tx)

    def update_view(self):
        private_key_to_sweep = viewModel.private_key_to_sweep.get_value()
        if self.state == SweepWalletViewModel.State.DECODE_KEY and private_key_to_sweep is None:
            message_view.set_visible(True)
            message_view.set_text(R.string.sweep_wallet_fragment_ wallet_unknown)

    def handle_decrypt(self):
        handler.post(maybe_decode_key_runnable)

    def handle_sweep(self):
        self.state = SweepWalletViewModel.State.PREPARATION
        wallet_to_sweep = viewModel.wallet_to_sweep.get_value()
        fees = viewModel.get_dynamic_fees().get_value()
        send_request = SendRequest.empty_wallet(wallet_to_sweep.fresh_receive_address())
        send_request.fee_per_kb = fees[FeeCategory.NORMAL]

    def on_insufficient_money(self, missing):
        self.state = SweepWalletViewModel.State.FAILED
        viewModel.show_dialog.set_value(DialogEvent.warn(R.string.sweep_wallet_fragment_insufficient_money_title,
                                                         R.string.sweep_wallet_fragment_insufficient_money_msg))

    def on_empty_wallet_failed():
        self.state = SweepWalletViewModel.State.FAILED
        viewModel.show_dialog.set_value(DialogEvent.warn(0, R.string.send_coins_error_msg, "Empty wallet failed"))

    def on_failure(self, exception):
        self.state = SweepWalletViewModel.State.FAILED
        viewModel.show_dialog.set_value(DialogEvent.warn(0, R.string.send_ coins_error_msg,
                                                         str(exception)))

class FakeTransaction:
    def __init__(self, params, tx_id, w_tx_id):
        super().__init__()
        this.tx_id = tx_id
        this.w_tx_id = w_tx_id

    @property
    def tx_id(self):
        return self._tx_id

    @property
    def w_tx_id(self):
        return self._w_tx_id