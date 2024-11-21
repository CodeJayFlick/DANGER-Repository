class ResourceTable:
    def __init__(self, reader, index):
        self.index = index
        old_index = reader.get_pointer()
        reader.set_pointer(index)
        
        alignment_shift_count = reader.read_short()
        
        type_list = []
        while True:
            rt = ResourceType(reader, self)
            if rt.get_type_id() == 0: break
            type_list.append(rt)
        types = [rt for rt in type_list]
        
        name_list = []
        while True:
            rn = ResourceName(reader)
            if rn.get_length() == 0: break
            name_list.append(rn)
        names = [rn for rn in name_list]
        
        reader.set_pointer(old_index)

    def get_alignment_shift_count(self):
        return self.alignment_shift_count

    def get_resource_types(self):
        return self.types

    def get_resource_names(self):
        return self.names

    def get_index(self):
        return self.index


class ResourceType:
    def __init__(self, reader, resource_table):
        pass  # This class is not implemented in the given Java code.

    def get_type_id(self):
        pass  # This method is not implemented in the given Java code.


class ResourceName:
    def __init__(self, reader):
        pass  # This class is not implemented in the given Java code.

    def get_length(self):
        pass  # This method is not implemented in the given Java code.
