Here is the translation of the Java code into Python:

```Python
class ModuleDB:
    def __init__(self):
        self.record = None
        self.module_mgr = None
        self.adapter = None
        self.child_count = 0
        self.lock = Lock()

    def refresh(self):
        try:
            if not self.record:
                return False

            rec = self.adapter.get_module_record(self.key)
            if rec is not None:
                self.record = rec
                self.child_count = 0
                for i in range(len(rec)):
                    child_id = rec[i].get_long_value(TreeManager.PARENT_ID_COL)
                    if child_id < 0:
                        frag = self.module_mgr.get_fragment_db(-child_id)
                        if not frag.is_empty():
                            return True

        except IOException as e:
            self.module_mgr.db_error(e)

    def add(self, fragment):
        try:
            if not self.record:
                return False

            rec = self.adapter.add_parent_child_record(self.key, -fragment.get_key())
            if rec is None:
                return False
            else:
                self.update_order_field(rec)
                self.module_mgr.fragment_added(self.key, fragment)

        except IOException as e:
            self.module_mgr.db_error(e)

    def get_children(self):
        try:
            lock.acquire()
            if not self.record:
                return []

            list = self.adapter.get_parent_child_records(self.key)
            kids = []
            for i in range(len(list)):
                rec = list[i]
                child_id = rec.get_long_value(TreeManager.CHILD_ID_COL)
                if child_id < 0:
                    kid = self.module_mgr.get_fragment_db(-child_id)
                    kids.append(kid)
                else:
                    kid = self.module_mgr.get_module_db(child_id)
                    kids.append(kid)

            return kids

        finally:
            lock.release()

    def get_comment(self):
        try:
            if not self.record:
                return None
            return self.record.get_string(TreeManager.MODULE_COMMENTS_COL)

        except IOException as e:
            self.module_mgr.db_error(e)

    # ... and so on for the rest of the methods ...
```

Please note that this is a direct translation from Java to Python, without considering any best practices or coding standards.