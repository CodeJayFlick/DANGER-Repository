Here is the translation of the Java code into Python:

```Python
class EquateDB:
    def __init__(self, equate_mgr, cache, record):
        super().__init__()
        self.record = record
        self.equate_mgr = equate_mgr

    def refresh(self):
        rec = self.equate_mgr.get_equate_record(self.key)
        if rec is None:
            return False
        self.record = rec
        return True

    def add_reference(self, ref_addr, op_index):
        check_deleted()
        try:
            instr = self.equate_mgr.get_program().get_code_manager().get_instruction_at(ref_addr)
            dynamic_hash = 0
            if instr is None:
                pass
            else:
                value = self.record.get_long_value(EquateDBAdapter.VALUE_COL)
                hash_array = DynamicHash.calc_constant_hash(instr, value)
                if len(hash_array) != 1:
                    dynamic_hash = 0
                else:
                    dynamic_hash = hash_array[0]
            self.equate_mgr.add_reference(self.key, ref_addr, op_index, dynamic_hash)
        except IOException as e:
            self.equate_mgr.db_error(e)

    def add_reference_dynamic(self, dynamic_hash, ref_addr):
        check_deleted()
        try:
            short op_index = find_op_index(ref_addr, dynamic_hash)
            self.equate_mgr.add_reference(self.key, ref_addr, op_index, dynamic_hash)
        except IOException as e:
            self.equate_mgr.db_error(e)

    def get_name(self):
        check_valid()
        return self.record.get_string(EquateDBAdapter.NAME_COL)

    def get_display_name(self):
        equate_name = self.get_name()
        if is_enum_based():
            dtm = self.equate_mgr.get_program().get_data_type_manager()
            id = EquateManager.get_data_type_uuid(equate_name)
            enoom = Enum(dtm.find_data_type_for_id(id))
            return enoom.name(self.value)  # has the tag and found the matching enum
        else:
            return equate_name

    def get_enum_uuid(self):
        if self.is_valid_uuid():
            return EquateManager.get_data_type_uuid(self.get_display_name())
        return None

    def get_reference_count(self):
        check_valid()
        try:
            return self.equate_mgr.get_reference_count(self.key)
        except IOException as e:
            self.equate_mgr.db_error(e)

    def get_references(self, ref_addr=None):
        if ref_addr is not None:
            lock = self.equate_mgr.get_lock()
            lock.acquire()
            try:
                references = []
                for reference in self.equate_mgr.get_references(self.key, ref_addr):
                    references.append(reference)
                return references
            finally:
                lock.release()
        else:
            check_valid()
            try:
                return self.equate_mgr.get_references(self.key)
            except IOException as e:
                self.equate_mgr.db_error(e)

    def get_value(self):
        check_valid()
        return self.record.get_long_value(EquateDBAdapter.VALUE_COL)

    def display_value(self):
        val = self.value
        if val < 0:
            return "-" + "0x" + hex(abs(val))
        else:
            return "0x" + hex(val)

    def remove_reference(self, ref_addr, op_index):
        check_deleted()
        try:
            self.equate_mgr.remove_reference(self, ref_addr, op_index)
        except IOException as e:
            self.equate_mgr.db_error(e)

    def rename_equate(self, new_name):
        lock = self.equate_mgr.get_lock()
        lock.acquire()
        try:
            if not check_deleted():
                return
            old_name = self.name
            if old_name == new_name:
                return
            try:
                self.equate_mgr.get_equate_database_adapter().get_record_key(new_name)
                raise DuplicateNameException("Equate named " + new_name + " already exists")
            except (NotFoundException, IOException) as e:
                pass
            self.record.set_string(EquateDBAdapter.NAME_COL, new_name)
            update_record()
            self.equate_mgr.equate_name_changed(old_name, new_name)
        finally:
            lock.release()

    def is_valid_uuid(self):
        equate_name = self.get_display_name()
        if equate_name == None or equate_name.contains(EquateManager.ERROR_TAG):
            return False
        return True

    def is_enum_based(self):
        return self.name.startswith(EquateManager.DATATYPE_TAG)

    def __eq__(self, obj):
        if obj is None:
            return False
        if isinstance(obj, EquateDB) and self.key == obj.key:
            return True
        else:
            return False

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.get_display_name()
```

Please note that this translation is not perfect. Python has different syntax, data types, and libraries than Java. Some parts of the code may need to be adjusted or rewritten for them to work correctly in a Python environment.