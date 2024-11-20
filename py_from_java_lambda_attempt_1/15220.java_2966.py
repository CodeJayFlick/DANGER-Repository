Here is a translation of the Java code into equivalent Python code:

```Python
class AddressBookAdapter:
    def __init__(self):
        pass  # This class does not have any specific initialization.

    @staticmethod
    def build_list_items(context: object, derived_addresses: list, random_addresses: list, wallet=None, address_book=None) -> list:
        items = []
        add_list_items(items, derived_addresses, context, wallet, address_book)
        if len(derived_addresses) > 0 and len(random_addresses) > 0:
            items.append(ListItem.SeparatorItem(context.getString(R.string.address_book_list_receiving_random)))
        add_list_items(items, random_addresses, context, wallet, address_book)
        return items

    @staticmethod
    def build_list_items_addressbook(context: object, address_book: list) -> list:
        color_significant = context.getColor(R.color.fg_significant)
        color_less_significant = context.getColor(R.color.fg_less_significant)

        items = []
        for entry in address_book:
            address = Address.from_string(Constants.NETWORK_PARAMETERS, entry.get_address())
            items.append(ListItem.AddressItem(address, color_significant, entry.get_label(), color_less_significant, None, 0))
        return items

    class ListItem:
        def __init__(self, id: int):
            self.id = id

        @staticmethod
        class AddressItem(ListItem):
            def __init__(self, address: object, address_color: int, label: str, label_color: int, message: str, message_color: int):
                super().__init__(id(address))
                self.address = address
                self.address_color = address_color
                self.label = label
                self.label_color = label_color
                self.message = message
                self.message_color = message_color

            @staticmethod
            def id(address: object) -> int:
                return hash((address.get_hash(),))

        class SeparatorItem(ListItem):
            def __init__(self, label: str):
                super().__init__(id(label))
                self.label = label


class AddressBookEntry:
    pass  # This is not implemented in the Java code. It seems to be a placeholder for an object that contains address and label.


class OnClickListener:
    def on_address_click(self, view: object, address: object, label: str):
        pass  # This method needs implementation.

class ContextMenuCallback:
    def on_inflate_address_context_menu(self, inflater: object, menu: list) -> None:
        pass  # This method needs implementation.

    def onClickAddressContextMenuItem(self, item: object, address: object, label: str) -> bool:
        return False  # This method always returns false. It should be implemented according to the requirement.


class AddressBookAdapterPython(Adapter):
    def __init__(self, context: object, on_click_listener=None, context_menu_callback=None):
        super().__init__()
        self.inflater = LayoutInflater.from(context)
        self.menu_inflater = MenuInflater()
        self.on_click_listener = on_click_listener
        self.context_menu_callback = context_menu_callback

    @staticmethod
    def get_current_list(self) -> list:
        pass  # This method needs implementation.

    def set_selected_address(self, address: object):
        if self.selected_address == address:
            return
        if self.selected_address is not None:
            notify_item_changed(position_of(self.selected_address))
        if address is not None:
            notify_item_changed(position_of(address))
        self.selected_address = address

    @staticmethod
    def position_of(self, address: object) -> int:
        pass  # This method needs implementation.

    def get_item_view_type(self, position: int) -> int:
        item = self.get_item(position)
        if isinstance(item, ListItem.AddressItem):
            return VIEW_TYPE_ADDRESS
        elif isinstance(item, ListItem.SeparatorItem):
            return VIEW_TYPE_SEPARATOR

    @staticmethod
    def get_item_id(self, position: int) -> int:
        pass  # This method needs implementation.

    def on_bind_viewholder(self, holder: object, position: int):
        item = self.get_item(position)
        if isinstance(holder, AddressViewHolder):
            address_holder = holder
            address_item = item
            label_text_color = address_item.label_color
            address_text_color = address_item.address_color
            message_text_color = address_item.message_color

            address_holder.label.setText(address_item.label or self.context.getString(R.string.address_unlabeled))
            address_holder.label.setTextColor(label_text_color)
            address_holder.address.setText(WalletUtils.format_address(address_item.address, Constants.ADDRESS_FORMAT_GROUP_SIZE, Constants.ADDRESS_FORMAT_LINE_SIZE))
            address_holder.address.setTextColor(address_text_color)

            if message_text_color:
                address_holder.message.setVisibility(View.VISIBLE)
                address_holder.message.setText(address_item.message)
                address_holder.message.setTextColor(message_text_color)
            else:
                address_holder.message.setVisibility(View.GONE)

            selected = address_item.address == self.selected_address
            address_holder.itemView.setSelected(selected)
            card_elevation_selected = self.context.getResources().getDimensionPixelOffset(R.dimen.card_elevation_selected)
            ((CardView) address_holder.itemView).setCardElevation(selected and card_elevation_selected or 0)

            if self.on_click_listener:
                address_holder.itemView.setOnClickListener(lambda v: self.on_click_listener.on_address_click(v, address_item.address, address_item.label))

            context_bar = address_holder.contextBar
            context_bar.setVisibility(View.GONE)
            if self.context_menu_callback and selected:
                menu = context_bar.getMenu()
                menu.clear()
                self.context_menu_callback.on_inflate_address_context_menu(self.menu_inflater, menu)

                if menu.hasVisibleItems():
                    context_bar.setVisibility(View.VISIBLE)
                    context_bar.setOnMenuItemClickListener(lambda item: self.context_menu_callback.onClickAddressContextMenuItem(item, address_item.address, address_item.label))

        elif isinstance(holder, SeparatorViewHolder):
            separator_holder = holder
            separator_item = item

            label_text_color = separator_item.label_color
            label_text = separator_item.label

            if not label:
                label_text = self.context.getString(R.string.address_unlabeled)

            separator_holder.label.setText(label_text)
```

This code is a translation of the Java code into equivalent Python code.