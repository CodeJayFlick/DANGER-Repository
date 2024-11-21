import logging
from datetime import datetime
from io import StringIO, BytesIO
from textwrap import dedent
from typing import Any, Dict, List

class BackupWalletDialogFragment:
    FRAGMENT_TAG = "BackupWalletDialogFragment"
    
    def __init__(self):
        self.activity: AbstractWalletActivity = None
        self.application: WalletApplication = None
        
        self.password_view: str = ""
        self.password_again_view: str = ""
        self.password_strength_view: str = ""
        self.password_mismatch_view: str = ""
        self.show_view: bool = False
        self.warning_view: str = ""

    def show(self, fm):
        dialog_fragment = BackupWalletDialogFragment()
        dialog_fragment.show(fm, self.FRAGMENT_TAG)

    @staticmethod
    def on_attach(context) -> None:
        super().on_attach(context)
        activity = context  # type: AbstractWalletActivity
        application = activity.get_wallet_application()  # type: WalletApplication

    def on_create(self, savedInstanceState: Dict[str, Any]) -> Dialog:
        view = LayoutInflater.from(activity).inflate(R.layout.backup_wallet_dialog, None)

        password_view = view.findViewById(R.id.backup_wallet_dialog_password)
        password_again_view = view.findViewById(R.id.backup_wallet_dialog_password_again)
        password_strength_view = view.findViewById(R.id.backup_wallet_dialog_password_strength)
        password_mismatch_view = view.findViewById(R.id.backup_wallet_dialog_password_mismatch)
        show_view = view.findViewById(R.id.backup_wallet_dialog_show)

        dialog_builder = DialogBuilder.custom(activity, R.string.export_keys_dialog_title, view)
        # dummies, just to make buttons show
        builder.set_positive_button(R.string.export_keys_dialog_button_export, None)
        builder.set_negative_button(R.string.button_cancel, None)

        dialog = builder.create()
        dialog.set_canceled_on_touch_outside(False)
        dialog.set_on_show_listener(lambda: self.on_show(dialog))

        return dialog

    def on_dismiss(self, dialog) -> None:
        password_view.remove_text_changed_listener(text_watcher)
        password_again_view.remove_text_changed_listener(text_watcher)

        show_view.set_on_checked_change(None)

        wipe_passwords()

        super().on_dismiss(dialog)

    @staticmethod
    def handle_go() -> None:
        # your code here

    def backup_wallet(self) -> None:
        password = password_view.get_text()
        password_again = password_again_view.get_text()

        if password_again == password:
            self.backup_password(password)
        else:
            password_mismatch_view.set_visibility(True)

    @staticmethod
    def wipe_passwords() -> None:
        # your code here

class SuccessDialogFragment(BackupWalletDialogFragment):
    FRAGMENT_TAG = "SuccessDialogFragment"
    
    def on_attach(self, context) -> None:
        super().on_attach(context)
        self.activity: AbstractWalletActivity = context  # type: Activity

    @staticmethod
    def show_dialog(fm, target) -> None:
        dialog_fragment = SuccessDialogFragment()
        bundle_args = Bundle()
        bundle_args.put_string("target", target)
        dialog_fragment.set_arguments(bundle_args)
        dialog_fragment.show(fm, self.FRAGMENT_TAG)

class ErrorDialogFragment(BackupWalletDialogFragment):
    FRAGMENT_TAG = "ErrorDialogFragment"
    
    def on_attach(self, context) -> None:
        super().on_attach(context)
        self.activity: AbstractWalletActivity = context  # type: Activity

    @staticmethod
    def show_dialog(fm, exception_message) -> None:
        dialog_fragment = ErrorDialogFragment()
        bundle_args = Bundle()
        bundle_args.put_string("exception_message", exception_message)
        dialog_fragment.set_arguments(bundle_args)
        dialog_fragment.show(fm, self.FRAGMENT_TAG)

class DialogBuilder:
    @staticmethod
    def custom(activity: AbstractWalletActivity, title: str, view) -> Dialog:
        # your code here

    @staticmethod
    def warn(activity: AbstractWalletActivity, title: str, message: str, exception_message: str) -> Dialog:
        # your code here

class LayoutInflater:
    @staticmethod
    def from(context: Any) -> 'LayoutInflater':
        return context  # type: LayoutInflater

class View:
    @staticmethod
    def findViewById(view: Any, id: int) -> Any:
        return view.findViewById(id)

class EditText:
    def get_text(self) -> str:
        return self.text

    def set_text(self, text: str) -> None:
        self.text = text

    def add_text_changed_listener(self, listener: TextWatcher) -> None:
        # your code here

    def remove_text_changed_listener(self, listener: TextWatcher) -> None:
        # your code here
