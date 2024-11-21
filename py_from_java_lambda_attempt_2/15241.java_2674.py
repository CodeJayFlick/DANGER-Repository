Here is a translation of the Java code into Python:

```Python
import logging
from typing import Optional

class EditAddressBookEntryFragment:
    FRAGMENT_TAG = type("EditAddressBookEntryFragment", (), {"FRAGMENT_TAG": "de.schildbach.wallet.ui.EditAddressBookEntryFragment"})

    KEY_ADDRESS = "address"
    KEY_SUGGESTED_ADDRESS_LABEL = "suggested_address_label"

    @classmethod
    def edit(cls, fm: object, address: str) -> None:
        cls.edit(fm, address, None)

    @classmethod
    def edit(cls, fm: object, address: str, suggested_address_label: Optional[str]) -> None:
        new_fragment = EditAddressBookEntryFragment(address, suggested_address_label)
        new_fragment.show(fm, cls.FRAGMENT_TAG)

    @classmethod
    def instance(cls, address: str, suggested_address_label: Optional[str] = None) -> "EditAddressBookEntryFragment":
        fragment = EditAddressBookEntryFragment()
        args = {"address": address}
        if suggested_address_label is not None:
            args["suggested_address_label"] = suggested_address_label
        fragment.set_args(args)
        return fragment

    def __init__(self, activity: object, wallet: str) -> None:
        self.activity = activity
        self.wallet = wallet

    @classmethod
    def get_logger(cls) -> logging.Logger:
        logger = logging.getLogger("EditAddressBookEntryFragment")
        return logger

    def on_attach(self, context: object) -> None:
        super().on_attach(context)
        self.activity = context
        application = self.activity.get_wallet_application()
        address_book_database = AddressBookDatabase.get_database(context).get_address_book_dao()
        wallet = application.get_wallet()

    def on_create(self, savedInstanceState: dict) -> None:
        logging.info("opening dialog %s", type(self).__name__)
        super().on_create(savedInstanceState)

    def on_create_dialog(self, savedInstanceState: Optional[dict]) -> object:
        args = self.get_args()
        address = Address.from_string(args["address"])
        suggested_address_label = args.get("suggested_address_label")

        inflater = LayoutInflater.from(self.activity)
        label = address_book_database.resolve_label(address.toString())

        is_add = label is None
        is_own = wallet.is_address_mine(address)

        title_res_id = R.string.edit_address_book_entry_dialog_title_edit if not is_own else (R.string.edit_address_book_entry_dialog_title_edit_2 if is_add else R.string.edit_address_book_entry_dialog_title_edit)
        view = inflater.inflate(R.layout.edit_address_book_entry_dialog, None)

        view_address = view.find(R.id.edit_address_book_entry_address)
        view_address.set_text(WalletUtils.format_address(address, Constants.ADDRESS_FORMAT_GROUP_SIZE, Constants.ADDRESS_FORMAT_LINE_SIZE))

        view_label = view.find(R.id.edit_address_book_entry_label)
        view_label.set_text(label if label is not None else suggested_address_label)

        dialog_builder = DialogBuilder.custom(self.activity, title_res_id, view)

        on_click_listener = lambda d, which: (d.dismiss() if which == DialogInterface.BUTTON_NEGATIVE or which == DialogInterface.BUTTON_NEUTRAL else
            address_book_database.insert_or_update(AddressBookEntry(address.toString(), view_label.get_text().trim())) if not is_add and view_label.get_text().trim() != "" else 
                None)

        dialog_builder.set_positive_button(R.string.button_edit, on_click_listener)
        if not is_add:
            dialog_builder.set_neutral_button(R.string.button_delete, on_click_listener)
        dialog_builder.set_negative_button(R.string.button_cancel, lambda d, which: (d.dismiss(),))

        return dialog_builder.create()

    def maybe_select_address(self, address: str) -> None:
        # Yes, this is quite hacky. The delay is needed because if an address is added it takes a moment to appear
        # in the address book.
        if isinstance(self.activity, AddressBookActivity):
            activity_view_model = ViewModelProvider(self.activity).get(AddressBookViewModel)
            self.activity.postDelayed(lambda: (activity_view_model.selected_address.set(address)), 250)

    def set_args(self, args: dict) -> None:
        pass

class DialogFragment:
    @classmethod
    def show(cls, fm: object, tag: str) -> None:
        super().show(fm, tag)
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.

Also, please note that there are several classes (like `Address`, `Wallet`, etc.) which were used in the original Java code but their equivalent counterparts do not exist in this translated Python code.