class NotifyFlushMemTable:
    def gen_mem_series(self, schema):
        return None

    def copy(self):
        return None

    def is_signal_mem_table(self):
        return True


# You can use this class like so:
memtable = NotifyFlushMemTable()
schema = "your_schema"
print(memtable.gen_mem_series(schema))  # prints: None
print(memtable.copy())  # prints: None
print(memtable.is_signal_mem_table())  # prints: True
