import logging

class WALFlushListener:
    def __init__(self, processor):
        self.processor = processor

    def on_flush_start(self, mem_table):
        if IoTDBDescriptor.get_instance().get_config().is_enable_wal():
            self.processor.log_node.notify_start_flush()

    def on_flush_end(self, mem_table):
        if not mem_table.is_signal_memtable() and IoTDBDescriptor.get_instance().get_config().is_enable_wal():
            self.processor.log_node.notify_end_flush()
