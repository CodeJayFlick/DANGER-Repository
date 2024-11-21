class DataComponent:
    def __init__(self, code_mgr, component_cache, address, addr, parent, component):
        super().__init__(code_mgr, component_cache, component.get_ordinal(), address, addr, component.get_data_type())
        self.index_in_parent = component.get_ordinal()
        self.parent = parent
        self.component = component
        self.level = parent.level + 1
        self.offset = component.get_offset()
        self.length = component.get_length()
        default_settings = component.get_default_settings()

    def __init__(self, code_mgr, component_cache, address, addr, parent, dt, ordinal, offset, length):
        super().__init__(code_mgr, component_cache, ordinal, address, addr, dt)
        self.index_in_parent = ordinal
        self.parent = parent
        self.offset = offset
        self.level = parent.level + 1
        self.length = length
        default_settings = dt.get_default_settings()

    def has_been_deleted(self, rec):
        if self.parent.has_been_deleted(None):
            return True
        pdt = self.parent.get_base_data_type()
        if isinstance(pdt, Composite):
            composite = pdt
            # If we are deleted, the parent may not have as many components as it used to,
            # so if our index is bigger than the number of components, then we are deleted.
            if self.index_in_parent >= composite.get_num_components():
                return True
            c = composite.get_component(self.index_in_parent)
            self.component = c
            self.data_type = c.get_data_type()
            self.offset = component.get_offset()
            self.length = component.get_length()
        elif isinstance(pdt, Array):
            a = pdt
            if self.index_in_parent >= a.get_num_elements():
                return True
            self.component = None
            self.data_type = a.get_data_type()
            self.length = a.get_element_length()
            self.offset = self.length * self.index_in_parent
        else:
            return True
        address = self.parent.get_address().add(self.offset)
        addr = self.parent.addr + self.offset
        base_data_type = get_base_data_type(self.data_type)
        if self.component is not None:
            default_settings = component.get_default_settings()
        else:
            default_settings = self.data_type.get_default_settings()
        bytes = None
        return False

    def get_component_path(self):
        if self.path is None:
            path = [0] * (self.level)
            parent_level = self.level - 1
            path[parent_level--] = self.index_in_parent

            data = self.parent
            while isinstance(data, DataComponent):
                dc = data
                path[parent_level--] = dc.index_in_parent
                data = dc.parent
        return path

    def get_field_name(self):
        if self.component is None:  # Is array?
            return "[" + str(self.index_in_parent) + "]"
        my_name = component.get_field_name()
        if my_name is None or len(my_name) == 0:
            my_name = component.get_default_field_name()
        return my_name

    def get_path_name(self):
        parent_path = self.parent.get_path_name()
        return get_component_name(parent_path)

    def get_component_path_name(self):
        parent_path = self.parent.get_component_path_name()
        return get_component_name(parent_path)

    @staticmethod
    def get_component_name(parent_path):
        string_buffer = StringBuffer()
        if parent_path is not None and len(parent_path) > 0:
            string_buffer.append(parent_path)
            if component is not None:  # Not an array?
                string_buffer.append('.')
            my_name = self.get_field_name()
            string_buffer.append(my_name)
        return str(string_buffer)

    def get_parent(self):
        return self.parent

    def get_root(self):
        return self.parent.get_root()

    def get_root_offset(self):
        return self.parent.get_root_offset() + self.offset

    def get_parent_offset(self):
        return self.offset

    def get_component_index(self):
        return self.index_in_parent

    @staticmethod
    def equals(obj):
        if obj is None:
            return False
        if isinstance(obj, DataComponent):
            data = obj
            if (self.index_in_parent != data.index_in_parent) or (self.offset != data.offset):
                return False
            return super().equals(obj)
        else:
            return False

    @staticmethod
    def get_preferred_cache_length():
        return 0  # Rely on parent for cached bytes

    def get_bytes(self, b, offset):
        lock.acquire()
        try:
            check_validity()
            return self.parent.get_bytes(b, self.offset + offset)
        finally:
            lock.release()

    @staticmethod
    def get_bytes():
        lock.acquire()
        try:
            check_validity()
            bytes = [0] * (self.length)
            if self.parent.get_bytes(bytes, 0) != self.length:
                raise MemoryAccessException("Couldn't get all bytes for CodeUnit")
            return bytes
        finally:
            lock.release()

    def get_byte(self, n):
        lock.acquire()
        try:
            check_validity()
            return self.parent.get_byte(self.offset + n)
        finally:
            lock.release()

    @staticmethod
    def get_comment(comment_type):
        cmt = super().get_comment(comment_type)
        if cmt is None and comment_type == CodeUnit.EOL_COMMENT and component is not None:
            cmt = component.get_comment()
        return cmt

    @staticmethod
    def data_settings_address():
        if self.parent.get_base_data_type() is Array:
            return self.parent.data_settings_address()
        else:
            return address


class StringBuffer:
    def __init__(self):
        self.string_buffer = ""

    def append(self, s):
        self.string_buffer += str(s)

    def toString(self):
        return self.string_buffer
