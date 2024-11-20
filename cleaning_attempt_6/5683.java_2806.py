class FileSystemRef:
    def __init__(self, fs):
        self.fs = fs
        self.ref_closed = False

    @property
    def filesystem(self):
        return self.fs

    def dup(self):
        return type(self)(self.fs)

    def close(self):
        if not self.is_ref_closed():
            self.fs.get_ref_manager().release(self)
            self.ref_closed = True

    def is_ref_closed(self):
        return self.ref_closed

    def __del__(self):
        if not self.is_ref_closed():
            print(f"Unclosed FilesytemRef: {self.fs}")
