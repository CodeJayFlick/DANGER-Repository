class VarnodeTableModel:
    def __init__(self):
        self.varnodes = []
        self.columns = []

    def get_name(self):
        return "Varnodes"

    def get_model_data(self):
        return self.varnodes

    def get_column_value_for_row(self, varnode, column_index):
        return self.columns[column_index].get_value_for_row(varnode)

    def get_column_count(self):
        return len(self.columns)

    def set_value_at(self, value, row_index, column_index):
        param = self.varnodes[row_index]
        varnode_col = self.columns[column_index]
        varnode_col.set_value(param, value)

    def is_cell_editable(self, row_index, column_index):
        return self.columns[column_index].is_cell_editable(row_index)

    def get_preferred_column_width(self, column_index):
        return self.columns[column_index].get_preferred_size()

    def get_column_name(self, column_index):
        return self.columns[column_index].name

class VarnodeCol:
    def __init__(self, name, preferred_size, class_type, is_editable):
        self.name = name
        self.preferred_size = preferred_size
        self.class_type = class_type
        self.is_editable = is_editable

    def get_preferred_size(self):
        return self.preferred_size

    def get_column_class(self):
        return self.class_type

    def set_value(self, varnode, value):
        pass  # do nothing by default

    def get_value_for_row(self, varnode):
        raise NotImplementedError("Subclass must implement this method")

    def is_cell_editable(self, row_index):
        return self.is_editable

    def get_name(self):
        return self.name


class TypeColumn(VarnodeCol):
    def __init__(self):
        super().__init__("Type", 60, VarnodeType, True)

    def get_value_for_row(self, varnode):
        return varnode.type

    def set_value(self, varnode, value):
        storage_model.set_varnode_type(varnode, value)


class LocationColumn(VarnodeCol):
    def __init__(self):
        super().__init__("Location", 60, Address, True)

    def get_value_for_row(self, varnode):
        register = varnode.register
        return register if register else varnode.address

    def set_value(self, varnode, value):
        if not value:
            pass
        elif isinstance(value, Address):
            storage_model.set_varnode(varnode, value, varnode.size)
        elif isinstance(value, Register):
            storage_model.set_varnode(varnode, value)
        elif isinstance(value, str):
            storage_model.set_varnode(varnode, value)
        else:
            raise AssertionError("Unexpected edit value")


class SizeColumn(VarnodeCol):
    def __init__(self):
        super().__init__("Size", 60, int, True)

    def get_value_for_row(self, varnode):
        return varnode.size

    def set_value(self, varnode, value):
        if not value:
            pass
        else:
            address = varnode.address
            size = int(value)
            if address:
                register = varnode.register
                if register and register.is_big_endian():
                    min_byte_size = register.minimum_byte_size
                    s = min(min_byte_size, size)
                    address += min_byte_size - s
        storage_model.set_varnode(varnode, address, size)


class StorageAddressModel:
    def __init__(self):
        self.varnodes = []

    def get_varnodes(self):
        return self.varnodes

    def set_varnodes(self, varnode_list):
        self.varnodes.clear()
        self.varnodes.extend(varnode_list)
        # fire_table_data_changed()  # Python doesn't have a direct equivalent of this method


class VarnodeInfo:
    pass  # This class is not implemented in the given Java code. It seems to be an abstract concept.
