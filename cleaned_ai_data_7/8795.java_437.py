class VTMatchTagDB:
    def __init__(self, session_db, cache, record):
        self.session_db = session_db
        self.record = record
        super().__init__(cache, record.key)

    def __str__(self):
        return self.get_name()

    def set_record(self, rec):
        if rec.key != self.key:
            raise ValueError("Key mismatch")
        self.record = rec

    def refresh(self):
        try:
            rec = self.session_db.get_tag_record(self.key)
        except Exception as e:
            self.session_db.db_error(e)
        if not rec:
            return False
        self.record = rec
        return True

    def get_record(self):
        return self.check_is_valid() and self.record or None

    @property
    def name(self):
        return self.record.get(TAG_NAME_COL)

    def compare_to(self, other_tag):
        return self.name.lower().casefold().__lt__(other_tag.name.lower().casefold())

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, obj):
        if id(self) == id(obj):
            return True
        elif not isinstance(obj, VTMatchTagDB):
            return False
        other = obj
        return self.name.__eq__(other.name)
