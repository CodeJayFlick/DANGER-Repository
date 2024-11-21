class VTMarkupItemTransferable:
    local_markup_item_flavor = create_local_markup_item_flavor()

    def create_local_markup_item_flavor():
        try:
            return DataFlavor('application/x-ghidra-vt-markup-item', 'Local markup item object')
        except Exception as e:
            print(f"Error: {e}")

    flavors = [local_markup_item_flavor]
    flavor_list = list(flavors)
    markup_item = None

    def __init__(self, markup_item):
        self.markup_item = markup_item

    def get_transfer_data(self, f):
        if f == self.local_markup_item_flavor:
            return self.markup_item
        else:
            raise UnsupportedFlavorException(f)

    def get_transfer_data_flavors(self):
        return [f for f in flavors]

    def is_data_flavor_supported(self, f):
        return f in flavor_list


class DataFlavorException(Exception):
    pass

class UnsupportedFlavorException(DataFlavorException):
    pass
