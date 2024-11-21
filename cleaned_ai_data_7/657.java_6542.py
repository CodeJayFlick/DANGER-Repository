class DbgWriteControlCommand:
    def __init__(self, manager, addr, buf, len, processor):
        self.addr = addr
        self.processor = processor
        self.buf = buf.copy()  # Assuming a similar functionality as duplicate()
        self.len = len

    def invoke(self):
        manager.get_data_spaces().write_control(processor, addr, buf, buf.remaining())
