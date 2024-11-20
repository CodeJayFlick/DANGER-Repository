Here is the translation of the Java code into Python:

```Python
import logging
from typing import Optional

class RaiseFeeDialogFragment:
    FRAGMENT_TAG = "RaiseFeeDialogFragment"
    KEY_TRANSACTION = "transaction"

    @classmethod
    def show(cls, fm: 'FragmentManager', transaction_id: bytes) -> None:
        new_fragment = cls.instance(transaction_id)
        new_fragment.show(fm, cls.FRAGMENT_TAG)

    @classmethod
    def instance(cls, transaction_id: bytes) -> 'RaiseFeeDialogFragment':
        fragment = RaiseFeeDialogFragment()
        args = {"transaction": transaction_id}
        fragment.setArguments(args)
        return fragment

    def __init__(self):
        self.activity = None  # type: AbstractWalletActivity
        self.application = None  # type: WalletApplication
        self.config = None  # type: Configuration
        self.fee_raise = None  # type: Optional[Coin]
        self.transaction = None  # type: Optional[Transaction]
        self.dialog = None  # type: Optional[AlertDialog]

    def on_attach(self, context: 'Context') -> None:
        super().onAttach(context)
        self.activity = context
        self.application = self.activity.get_wallet_application()
        self.config = self.application.get_configuration()

    def on_create(self, savedInstanceState: dict) -> None:
        super().onCreate(savedInstanceState)
        logging.info("opening dialog {}".format(type(self).__name__))

        wallet_activity_view_model = ViewModelProvider(self.activity).get(AbstractWalletActivityViewModel)
        wallet_activity_view_model.wallet.observe(self, lambda wallet: self.update_view())
        transaction = wallet_activity_view_model.get_transaction(Sha256Hash.wrap(getArguments().getByteArray(RaiseFeeDialogFragment.KEY_TRANSACTION)))
        update_view()

    def on_create_dialog(self) -> 'AlertDialog':
        view = LayoutInflater.from(self.activity).inflate(R.layout.raise_fee_dialog, None)

        message_view = view.findViewById(R.id.raise_fee_dialog_message)
        password_group = view.findViewById(R.id.raise_fee_dialog_password_group)
        password_view = view.findViewById(R.id.raise_fee_dialog_password)
        bad_password_view = view.findViewById(R.id.raise_fee_dialog_bad_password)

        dialog_builder = DialogBuilder.custom(self.activity, R.string.raise_fee_dialog_title, view)
        # dummies, just to make buttons show
        dialog_builder.set_positive_button(R.string.raise_fee_dialog_button_raise, None)
        dialog_builder.set_negative_button(R.string.button_dismiss, None)
        dialog_builder.setCancelable(False)

        dialog = dialog_builder.create()
        dialog.setOnShowListener(lambda d: self.on_show(d))
        return dialog

    def on_dismiss(self, dialog: 'DialogInterface') -> None:
        self.dialog = None
        wipe_passwords()

    def destroy(self) -> None:
        background_thread.get_looper().quit()
        super().destroy()

    def handle_go(self) -> None:
        state = State.DECRYPTING
        update_view()

        wallet = wallet_activity_view_model.wallet.value

        if wallet.is_encrypted():
            derive_key_task = DeriveKeyTask(background_handler, application.scrypt_iterations_target())
            derive_key_task.on_success(lambda encryption_key, was_changed: self.do_raise_fee(wallet, encryption_key))
            derive_key_task.derive_key(wallet, password_view.text)
        else:
            do_raise_fee(wallet, None)

    def do_raise_fee(self, wallet: 'Wallet', encryption_key: Optional['KeyParameter']) -> None:
        # construct child-pays-for-parent
        output_to_spend = find_spendable_output(wallet, transaction, fee_raise)
        if output_to_spend is not None:
            send_request = SendRequest.for_tx(transactionToSend)
            send_request.aes_key = encryption_key

            try:
                wallet.sign_transaction(send_request)

                logging.info("raise fee: cpfp {}".format(transactionToSend))
                wallet_activity_view_model.broadcast_transaction(transactionToSend)

                state = State.DONE
                update_view()

                self.dismiss()
            except KeyCrypterException as e:
                bad_password_view.setVisibility(View.VISIBLE)
                state = State.INPUT
                update_view()
                password_view.requestFocus()
        else:
            message_view.setText(R.string.raise_fee_dialog_cant_raise)
            password_group.setVisibility(View.GONE)

    def wipe_passwords(self) -> None:
        password_view.text = ""

    def update_view(self) -> None:
        if self.dialog is None:
            return

        wallet = wallet_activity_view_model.wallet.value
        needs_password = wallet.is_encrypted()

        if wallet is None or transaction is None or fee_raise is None:
            message_view.setText(R.string.raise_fee_dialog_determining_fee)
            password_group.setVisibility(View.GONE)
        elif find_spendable_output(wallet, transaction, fee_raise) is None:
            message_view.setText(R.string.raise_fee_dialog_cant_raise)
            password_group.setVisibility(View.GONE)
        else:
            message_view.setText(self.get_string(R.string.raise_fee_dialog_message, self.config.format().format(fee_raise)))
            password_group.setVisibility(needs_password and View.VISIBLE or View.GONE)

    def on_show(self, dialog: 'DialogInterface') -> None:
        positive_button = dialog.get_button(0)
        negative_button = dialog.get_button(1)

        if state == State.INPUT:
            positive_button.setText(R.string.raise_fee_dialog_button_raise)
            positive_button.setEnabled(not needs_password or password_view.text.length() > 0 and wallet is not None and transaction is not None and fee_raise is not None and find_spendable_output(wallet, transaction, fee_raise) is not None)
            negative_button.setEnabled(True)
        elif state == State.DECRYPTING:
            positive_button.setText(R.string.raise_fee_dialog_state_decrypting)
            positive_button.setEnabled(False)
            negative_button.setEnabled(False)
        else:
            positive_button.setText(R.string.raise_fee_dialog_state_done)
            positive_button.setEnabled(False)
            negative_button.setEnabled(False)

    def get_string(self, id: int) -> str:
        return self.activity.get_resources().getString(id)

    @staticmethod
    def fee_can_likely_be_raised(wallet: 'Wallet', transaction: Transaction) -> bool:
        if transaction.confidence.depth_in_blocks > 0:
            return False

        if WalletUtils.is_pay_to_many_transaction(transaction):
            return False

        # We don't know dynamic fees here, so we need to guess.
        if find_spendable_output(wallet, transaction, Transaction.DEFAULT_TX_FEE) is None:
            return False

        return True

    @staticmethod
    def find_spendable_output(wallet: 'Wallet', transaction: Transaction, minimum_output_value: Coin) -> Optional[TransactionOutput]:
        for output in transaction.get_outputs():
            if output.is_mine(wallet) and output.is_available_for_spending() and output.value > minimum_output_value:
                return output

        return None
```

Please note that this is a direct translation of the Java code into Python, without considering any potential issues or improvements.