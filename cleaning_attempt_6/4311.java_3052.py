class StackPieceDataType:
    def __init__(self, var, data_mgr):
        super().__init__()
        self.variable = var

    @staticmethod
    def get_piece_name(var):
        storage = var.get_variable_storage()
        stack_varnode = storage.get_last_varnode()
        piece_len = stack_varnode.get_size()
        return f"{var.get_data_type().name}:{piece_len} (piece)"

    def clone(self, dtm):
        if dtm == self.data_manager:
            return self
        raise ValueError("May not be cloned with new DataTypeManager")

    def copy(self, dtm):
        raise NotImplementedError

    def set_category_path(self, path):
        raise NotImplementedError

    def set_name(self, name):
        raise NotImplementedError

    def set_name_and_category(self, path, name):
        raise NotImplementedError

    def get_mnemonic(self, settings):
        return f"{self.variable.get_data_type().get_mnemonic(settings)}:{self.length}"

    @property
    def length(self):
        storage = self.variable.get_variable_storage()
        stack_varnode = storage.get_last_varnode()
        return stack_varnode.get_size()

    def get_description(self):
        # We could provide a description if needed
        return None

    def get_value(self, buf, settings, length):
        return None

    def get_representation(self, buf, settings, length):
        return None

    def is_equivalent(self, dt):
        return False

    def data_type_size_changed(self, dt):
        pass

    def data_type_deleted(self, dt):
        pass

    def data_type_replaced(self, dt1, dt2):
        pass

    def data_type_name_changed(self, dt, old_name):
        pass

    def depends_on(self, dt):
        return False
