import logging
from typing import Optional

class RestoreWalletDialogFragment:
    FRAGMENT_TAG = "RestoreWalletDialogFragment"
    KEY_BACKUP_URI = "backup_uri"

    def __init__(self):
        self.activity: AbstractWalletActivity = None  # type hinting for IDEs
        self.application: WalletApplication = None
        self.content_resolver: ContentResolver = None
        self.config: Configuration = None

    @staticmethod
    def show_pick(fm) -> None:
        new_fragment = RestoreWalletDialogFragment()
        new_fragment.show(fm, RestoreWalletDialogFragment.FRAGMENT_TAG)

    @staticmethod
    def show(fm, backup_uri: Uri) -> None:
        new_fragment = RestoreWalletDialogFragment()
        args = Bundle()
        args.putParcelable(RestoreWalletDialogFragment.KEY_BACKUP_URI, check_not_none(backup_uri))
        new_fragment.set_arguments(args)
        new_fragment.show(fm, RestoreWalletDialogFragment.FRAGMENT_TAG)

    def on_attach(self, context: Context) -> None:
        super().on_attach(context)
        self.activity = AbstractWalletActivity(context)
        self.application = WalletApplication()
        self.content_resolver = application.get_content_resolver()
        self.config = application.get_configuration()

    def on_create(self, savedInstanceState: Optional[Bundle]) -> None:
        log.info("Opening dialog")
        self.viewModel = ViewModelProvider(self).get(RestoreWalletViewModel)

        self.viewModel.show_success_dialog.observe(self, lambda show_encrypted_message: SuccessDialogFragment.show_dialog(get_parent_fragment_manager(), show_encrypted_message))
        self.viewModel.show_failure_dialog.observe(self, lambda message: FailureDialogFragment.show_dialog(get_parent_fragment_manager(), message, self.viewModel.backup_uri.value))

    def on_activity_result(self, request_code: int, result_code: int, data: Optional[Intent]) -> None:
        if request_code == RestoreWalletDialogFragment.REQUEST_CODE_OPEN_DOCUMENT:
            if result_code == Activity.RESULT_OK:
                if data is not None:
                    self.viewModel.backup_uri.value = data.get_data()
                else:
                    log.info("Didn't get uri")
                    dismiss()
                    maybe_finish_activity()

    def on_create_dialog(self, savedInstanceState: Optional[Bundle]) -> Dialog:
        view = LayoutInflater.from(self.activity).inflate(R.layout.restore_wallet_dialog, None)
        message_view = view.findViewById(R.id.restore_wallet_dialog_message)
        password_view = view.findViewById(R.id.restore_wallet_dialog_password)
        show_view = view.findViewById(R.id.restore_wallet_dialog_show)

        dialog_builder = DialogBuilder.custom(self.activity, R.string.import_keys_dialog_title, view)
        dialog_builder.set_positive_button(
            R.string.import_keys_dialog_button_import,
            lambda dialog: self.handle_restore(password_view.get_text().trim())
        )
        dialog_builder.set_negative_button(
            R.string.button_cancel,
            lambda dialog: (password_view.set_text(None); maybe_finish_activity())
        )

        return dialog_builder.create()

    def handle_restore(self, password) -> None:
        backup_uri = self.viewModel.backup_uri.value
        if backup_uri is not None:
            try:
                cipher_in = BufferedReader(InputStreamReader(backup_uri.open_input_stream(), StandardCharsets.UTF_8))
                cipher_text = StringBuilder()
                CharStreams.copy(cipher_in, cipher_text)
                cipher_in.close()

                plain_text = Crypto.decrypt_bytes(cipher_text.toString(), password.encode())
                is = ByteArrayInputStream(plain_text)

                restored_wallet = WalletUtils.restore_wallet_from_protobuf(is, Constants.NETWORK_PARAMETERS)
                self.application.replace_wallet(restored_wallet)
                config.disarm_backup_reminder()
                config.update_last_restore_time()

                log.info("Successfully restored encrypted wallet from external source")
            except IOException as x:
                log.info(f"Problem restoring wallet: {x}")
        else:
            message = "No backup data provided"
            self.viewModel.show_failure_dialog.value = Event(message)
            log.info(f"Problem restoring wallet: {message}")

    def restore_wallet_from_encrypted(self, cipher: InputStream, password) -> Wallet:
        try:
            plain_text = Crypto.decrypt_bytes(cipher.read().decode(), password.encode())
            return WalletUtils.restore_wallet_from_protobuf(ByteArrayInputStream(plain_text), Constants.NETWORK_PARAMETERS)
        except IOException as x:
            log.info(f"Problem restoring wallet from encrypted data: {x}")
