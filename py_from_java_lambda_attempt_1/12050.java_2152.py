Here's a translation of your Java code into equivalent Python:

```Python
class RefList:
    BIG_REF_LIST_THRESHOLD = 1700

    def __init__(self, key, address, adapter, addr_map, program, cache, is_from):
        self.address = address
        self.adapter = adapter
        self.addr_map = addr_map
        self.program = program
        self.is_from = is_from
        super().__init__(cache, key)

    def add_ref(self, from_addr, to_addr, ref_type, op_index, symbol_id, 
                is_primary, source_type, is_offset, is_shift, offset_or_shift):
        raise NotImplementedError

    def update_ref_type(self, addr, op_index, ref_type):
        raise NotImplementedError

    def get_ref(self, address, op_index):
        raise NotImplementedError

    def remove_ref(self, addr, op_index):
        raise NotImplementedError

    def is_empty(self):
        raise NotImplementedError

    def set_primary(self, ref, b):
        raise NotImplementedError

    def get_refs(self):
        raise NotImplementedError

    def all_refs(self):
        raise NotImplementedError

    def num_refs(self):
        raise NotImplementedError

    def primary_ref(self, op_index):
        raise NotImplementedError

    def remove_all(self):
        raise NotImplementedError

    def set_symbol_id(self, ref, symbol_id):
        raise NotImplementedError

    def has_reference(self, op_index):
        raise NotImplementedError

    def reference_level(self):
        raise NotImplementedError

    def check_ref_list_size(self, cache, new_space_required):
        if self.adapter and (self.num_refs() + new_space_required) >= RefList.BIG_REF_LIST_THRESHOLD:
            cache.delete(self.key)
            big_ref_list = BigRefListV0(self.address, self.adapter, 
                                         self.addr_map, self.program, cache, self.is_from)
            big_ref_list.add_refs(self.get_refs())
            return big_ref_list
        return self

class BigRefListV0(RefList):
    pass
```

Please note that the `add_ref`, `update_ref_type`, `get_ref`, `remove_ref`, `is_empty`, `set_primary`, `get_refs`, `all_refs`, `num_refs`, `primary_ref`, `remove_all`, `set_symbol_id`, `has_reference` and `reference_level` methods are abstract in Java, so I've translated them into Python as well.