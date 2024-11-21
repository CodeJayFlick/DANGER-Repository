class PseudoDataComponent:
    def __init__(self, program, address, parent, component):
        self.parent = parent
        self.component = component
        try:
            super().__init__(program, address, component.get_data_type(), WrappedMemBuffer(component.mem_buffer, component.offset))
        except (AddressOverflowException, MemoryAccessException) as e:
            print(f"Error: {e}")
        
    def get_component_path(self):
        if not hasattr(self, 'path'):
            self.path = [self.level - 1]
            parent_level = self.level - 2
            while self.parent is not None and isinstance(self.parent, PseudoDataComponent):
                self.path.insert(0, self.parent.index_in_parent)
                self.parent = self.parent.parent
        return self.path

    def get_field_name(self):
        if self.component is None:
            return f"[{self.index_in_parent}]"
        my_name = self.component.get_field_name()
        if not my_name or len(my_name) == 0:
            my_name = "field" + str(component.offset)
        return my_name

    def get_path_name(self):
        parent_path = self.parent.path_name
        return self.get_component_name(parent_path)

    def get_component_path_name(self):
        parent_path = self.parent.component_path_name
        return self.get_component_name(parent_path)

    @staticmethod
    def get_component_name(parent_path):
        name_buffer = StringBuffer()
        if parent_path and len(parent_path) > 0:
            name_buffer.append(parent_path)
            if not isinstance(component, PseudoDataComponent):  # not an array?
                name_buffer.append('.')
        my_name = self.get_field_name()
        if not my_name or len(my_name) <= 0:
            name_buffer.append("field")
            name_buffer.append(str(self.component.offset))
        else:
            name_buffer.append(my_name)
        return str(name_buffer)

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        if isinstance(value, PseudoDataComponent) or value is None:
            self._parent = value
        else:
            raise ValueError("Parent must be a PseudoDataComponent instance")

    @property
    def component(self):
        return self._component

    @component.setter
    def component(self, value):
        if isinstance(value, DataTypeComponent) or value is None:
            self._component = value
        else:
            raise ValueError("Component must be a DataTypeComponent instance")
