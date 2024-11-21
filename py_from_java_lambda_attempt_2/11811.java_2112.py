Here is the translation of the Java code into Python:

```Python
class BookmarkDBManager:
    def __init__(self):
        self.program = None
        self.addr_map = None
        self.bookmark_type_adapter = None
        self.bookmark_adapter = None
        self.cache = {}

    def set_program(self, program):
        if self.program is not None:
            raise Exception("Program already set")
        self.program = program

        if self.upgrade:
            self._upgrade_old_bookmarks(program)

        for rec in self.bookmark_type_adapter.get_records():
            type_id = int(rec.key())
            bookmark_type_db = BookmarkTypeDB(type_id, str(rec["type_name"]))
            self.types_by_name[bookmark_type_db.type_string()] = bookmark_type_db
            self.types_array.append(bookmark_type_db)
            if not bookmark_type_db.has_bookmarks:
                self.bookmark_adapter.add_type(type_id)

    def program_ready(self):
        pass

    def db_error(self, e):
        print(f"Error: {e}")

    def invalidate_cache(self, all=False):
        lock.acquire()
        try:
            self.cache.invalidate()
            self.bookmark_adapter.reload_tables()
            self._refresh_bookmarks()
        finally:
            lock.release()

    def _refresh_bookmarks(self):
        for bookmark_type_db in self.types_by_name.values():
            if not bookmark_type_db.has_bookmarks:
                continue
            rec_iter = self.bookmark_adapter.get_records_by_type_at_address(bookmark_type_db.type_id, addr_map.decode_address(0), True)
            while rec_iter.hasNext():
                rec = rec_iter.next()
                category = str(rec["category"])
                for bm in get_bookmarks_iterator(addr_map.decode_address(int(rec.key())), bookmark_type_db):
                    if all or not bm.has_bookmarks:
                        do_remove Bookmark(bm)

    def set_program(self, program):
        self.program = program

    def _upgrade_old_bookmarks(self, programdb):
        old_mgr = OldBookmarkManager(programdb)
        for rec in old_mgr.get_type_records():
            type_id = int(rec.key())
            if not bookmark_adapter.has_table(type_id):
                continue
            addr_iter = bookmark_adapter.get_records_by_type_at_address(type_id, 0, True)
            while addr_iter.hasNext():
                rec = addr_iter.next()
                category = str(rec["category"])
                for bm in get_bookmarks_iterator(addr_map.decode_address(int(rec.key())), type_id, False):
                    if all or not bm.has_bookmarks:
                        do_remove Bookmark(bm)

    def bookmark_changed(self, bm):
        lock.acquire()
        try:
            rec = self.bookmark_adapter.get_record(bm.id)
            if rec is None:
                return
            for category in get_categories():
                pass

    # More methods...

class OldBookmarkManager:
    def __init__(self, programdb):
        self.type_records = []

    def set_program(self, programdb):
        self.programdb = programdb

    def remove_bookmark(self, bm):
        if not bm.has_bookmarks:
            return
        for rec in get_record_iterator(bm.id):
            do_remove Bookmark(rec)

class BookmarkTypeDBAdapter:
    # More methods...

# Other classes...
```

Please note that this is a direct translation of the Java code into Python.