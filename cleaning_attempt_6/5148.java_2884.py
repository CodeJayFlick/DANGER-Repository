class VS_VERSION_CHILD:
    def __init__(self, reader, relative_offset, parent_name, value_map):
        self.relative_offset = relative_offset
        self.parent_name = parent_name
        orig_index = reader.get_pointer_index()
        
        child_size = reader.read_next_short()
        if child_size == 0:
            return
        
        child_value_size = reader.read_next_short()
        child_value_type = reader.read_next_short()

        child_name = reader.read_next_unicode_string()

        value_alignment = reader.align(4)

        has_children = False
        if parent_name is None:
            self.child_data_type = child_name
            has_children = True
        elif parent_name == "StringFileInfo":
            self.child_data_type = "StringTable"
            has_children = True
        elif parent_name == "VarFileInfo":
            self.child_data_type = "Var"
            if child_value_size > 0:
                self.child_value = f"{reader.read_next_int():x}"
        
        if has_children:
            while reader.get_pointer_index() < orig_index + child_size:
                child = VS_VERSION_CHILD(reader, reader.get_pointer_index() - orig_index, self.child_data_type, value_map)
                if not hasattr(self, 'children'):
                    self.children = []
                self.children.append(child)

    def to_data_type(self):
        if self.child_name is None or self.child_data_type is None:
            return None
        
        struct = StructureDataType(self.child_data_type, 0)
        struct.add(WORD, "wLength", None)
        struct.add(WORD, "wValueLength", None)
        struct.add(WORD, "wType", None)
        struct.set_category_path(CategoryPath("/PE"))
        
        return struct

    def get_children(self):
        if not hasattr(self, 'children'):
            self.children = []
        arr = [child for child in self.children]
        return arr
    
    def get_relative_offset(self):
        return self.relative_offset
    
    def get_child_name(self):
        return self.child_name
    
    def get_child_size(self):
        return self.child_size
    
    def get_value_relative_offset(self):
        if not hasattr(self, 'child_value'):
            return 0
        
        return ((len(self.child_name) + 1) * 2) + self.value_alignment + 6

    def get_name_relative_offset(self):
        if self.child_size == 0:
            return 0
        return 6
    
    def value_is_unicode_string(self):
        return hasattr(self, 'child_value') and self.child_data_type == "StringInfo"
    
    def value_is_dword(self):
        return hasattr(self, 'child_value') and self.child_data_type == "Var"

class StructureDataType:
    def __init__(self, child_data_type, offset):
        self.child_data_type = child_data_type
        self.offset = offset
    
    def add(self, data_type, name, value=None):
        pass

    def set_category_path(self, category_path):
        pass


# Example usage:

class FactoryBundledWithBinaryReader:
    def __init__(self):
        pass
    
    def get_pointer_index(self):
        return 0
    
    def read_next_short(self):
        return 1
    
    def read_next_unicode_string(self):
        return "test"
    
    def align(self, alignment):
        return 4

reader = FactoryBundledWithBinaryReader()
value_map = {}
child = VS_VERSION_CHILD(reader, 10, None, value_map)
print(child.get_child_name())
