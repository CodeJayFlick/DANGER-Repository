class AddressKeyAddressIterator:
    def __init__(self, key_iter=None, forward=True, addr_map=None, err_handler=None):
        self.key_iter = key_iter
        self.addr_map = addr_map
        self.forward = forward
        self.err_handler = err_handler

    def has_next(self):
        try:
            if self.key_iter is None or (self.forward and not self.key_iter.has_next() or not self.forward and not self.key_iter.has_previous()):
                return False
            return True
        except Exception as e:
            if self.err_handler:
                self.err_handler(e)
        return False

    def next(self):
        if self.key_iter is None:
            return None
        addr = None
        try:
            if self.forward:
                addr = self.addr_map.decode_address(next(self.key_iter))
            else:
                addr = self.addr_map.decode_address(prev(self.key_iter))
        except (StopIteration, Exception) as e:
            if self.err_handler:
                self.err_handler(e)
        return addr

    def remove(self):
        raise NotImplementedError("remove is not supported")

    def __iter__(self):
        return self
