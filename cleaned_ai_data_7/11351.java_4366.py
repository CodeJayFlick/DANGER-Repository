class ProgramMappedLoadImage:
    def __init__(self, pmm):
        self.pmm = pmm

    def load_fill(self, bytes, size, addr, offset, generate_initialized_mask=False):
        return self.pmm.read(bytes, size, addr, offset, generate_initialized_mask)

    def write_back(self, bytes, size, addr, offset):
        self.pmm.write(bytes, size, addr, offset)

    def dispose(self):
        self.pmm.dispose()
