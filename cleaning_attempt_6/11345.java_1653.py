class FilteredMemoryState:
    def __init__(self, lang):
        self.lang = lang
        self.filter_enabled = True  # used to prevent filtering filter queries
        self.filter = None

    def get_chunk(self, res, spc, off, size, stop_on_unintialized=False):
        read_len = super().get_chunk(res, spc, off, size, stop_on_unintialized)
        if self.filter_enabled and self.filter is not None:
            try:
                self.filter.filter_read(spc, off, read_len, res)
            finally:
                self.filter_enabled = True
        return read_len

    def set_chunk(self, res, spc, off, size):
        super().set_chunk(res, spc, off, size)
        if self.filter_enabled and self.filter is not None:
            try:
                self.filter.filter_write(spc, off, size, res)
            finally:
                self.filter_enabled = True

    def set_filter(self, filter):
        old_filter = self.filter
        self.filter = filter
        return old_filter
