class FragmentDB:
    def __init__(self, module_mgr, cache, record, addr_set):
        super().__init__(cache, record.key)
        self.module_mgr = module_mgr
        self.record = record
        self.addr_set = addr_set
        self.adapter = module_mgr.get_group_db_adapter()
        self.lock = module_mgr.get_lock()

    def refresh(self):
        try:
            rec = self.adapter.get_fragment_record(self.key)
            if rec is not None:
                self.record = rec
                self.addr_set = self.module_mgr.get_fragment_address_set(self.key)
                return True
        except IOException as e:
            self.module_mgr.db_error(e)

    def contains(self, code_unit):
        return self.contains(code_unit.min_address())

    def get_code_units(self):
        if not self.is_valid():
            raise Exception("Invalid FragmentDB object")
        return self.module_mgr.get_code_units(self)

    def get_comment(self):
        with self.lock:
            try:
                if not self.is_valid():
                    raise Exception("Invalid FragmentDB object")
                return self.record.get_string(TreeManager.FRAGMENT_COMMENTS_COL)
            finally:
                self.lock.release()

    # ... and so on for all the methods
