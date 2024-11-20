class FlushListener:
    def on_flush_start(self, mem_table):
        pass

    def on_flush_end(self, mem_table):
        pass


class EmptyListener(FlushListener):
    INSTANCE = EmptyListener()

    def __init__(self):
        pass

    def on_flush_start(self, mem_table):
        # do nothing
        pass

    def on_flush_end(self, mem_table):
        # do nothing
        pass
