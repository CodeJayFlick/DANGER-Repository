class BookmarkDB:
    def __init__(self, mgr, cache, record):
        self.mgr = mgr
        self.record = record

    def __str__(self):
        return f"{self.get_type_string()} - {self.get_category()} - {self.get_comment()} - {self.get_address()}"

    def set_record(self, rec):
        if rec.key != self.key:
            raise ValueError("Key mismatch")
        self.record = rec

    @property
    def id(self):
        return self.key

    @property
    def address(self):
        self.check_is_valid()
        return self.mgr.get_address(self.record.get_long_value(BookmarkDBAdapter.ADDRESS_COL))

    @property
    def type_(self):
        self.check_is_valid()
        return self.mgr.get_bookmark_type((self.key >> BookmarkDBAdapter.TYPE_ID_OFFSET) & 0xFFFFFFFF)

    @property
    def type_string(self):
        return str(self.type_).upper()

    @property
    def category(self):
        return self.record.get_string(BookmarkDBAdapter.CATEGORY_COL)

    def set_comment(self, comment):
        if not self.is_deleted():
            if comment is None:
                comment = ""
            if comment != self.record.get_string(BookmarkDBAdapter.COMMENT_COL):
                self.record.set_string(BookmarkDBAdapter.COMMENT_COL, comment)
                self.mgr.bookmark_changed(self)

    @property
    def comment(self):
        return self.record.get_string(BookmarkDBAdapter.COMMENT_COL)

    def set(self, category=None, comment=None):
        if not self.is_deleted():
            if category is None:
                category = ""
            if comment is None:
                comment = ""
            if (comment != self.comment or category != self.category) and \
               (category != "" or comment != ""):
                self.record.set_string(BookmarkDBAdapter.CATEGORY_COL, category)
                self.record.set_string(BookmarkDBAdapter.COMMENT_COL, comment)
                self.mgr.bookmark_changed(self)

    def refresh(self):
        return self.refresh(None)

    def refresh_(self, rec=None):
        if rec is None:
            rec = self.mgr.get_record(self.key)
        if rec is None:
            return False
        self.record = rec
        return True

    @property
    def record_(self):
        return self.check_is_valid() and self.record or None

    def __hash__(self):
        return int(self.key)

    def __eq__(self, other_bm):
        if not isinstance(other_bm, BookmarkDB):
            return NotImplemented
        rc = self.address == other_bm.address
        if rc:
            return False
        rc = self.type_string == other_bm.type_string
        if rc:
            return False
        rc = self.category == other_bm.category
        if rc:
            return False
        return self.comment == other_bm.comment

    def __lt__(self, other_bm):
        if not isinstance(other_bm, BookmarkDB):
            return NotImplemented
        rc = self.address < other_bm.address
        if rc:
            return True
        rc = self.type_string < other_bm.type_string
        if rc:
            return True
        rc = self.category < other_bm.category
        if rc:
            return True
        return self.comment < other_bm.comment

    def check_is_valid(self):
        pass  # Implement this method in your subclass.

class BookmarkDBManager:
    pass  # This class is not implemented here, but you should implement it to provide the necessary methods.
