class MSRICHProductIDDataType:
    def __init__(self, compid):
        self.compid = compid

    @property
    def category_path(self):
        return "/PE"

    @category_path.setter
    def category_path(self, value):
        pass  # ignored in the original code

    @property
    def name(self):
        return "MSProductID"

    @name.setter
    def name(self, value):
        pass  # ignored in the original code

    def clone(self):
        return MSRICHProductIDDataType(self.compid)

    def copy(self):
        return self.clone()

    def set_category_path(self, path):
        pass  # ignored in the original code

    def set_name(self, name):
        pass  # ignored in the original code

    def get_mnemonic(self, settings):
        return "Product ID"

    @property
    def length(self):
        return 2

    @length.setter
    def length(self, value):
        pass  # ignored in the original code

    def description(self):
        return "Product ID"

    def get_value(self, buf, settings, length):
        return self.compid.get_product_id()

    def get_representation(self, buf, settings, length):
        return self.compid.get_product_description()

    def is_equivalent(self, dt):
        if dt == self:
            return True
        elif dt is None:
            return False
        else:
            return isinstance(dt, MSRICHProductIDDataType)

    def data_type_size_changed(self, dt):
        pass  # ignored in the original code

    def data_type_deleted(self, dt):
        pass  # ignored in the original code

    def data_type_replaced(self, old_dt, new_dt):
        pass  # ignored in the original code

    def data_type_name_changed(self, dt, old_name):
        pass  # ignored in the original code

    def depends_on(self, dt):
        return False
