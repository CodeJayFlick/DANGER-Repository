Here is the translation of the Java code to Python:
```
class TableStatistics:
    def __init__(self):
        self.name = None
        self.index_column = -1
        self.buffer_count = 0
        self.size = 0
        self.interior_node_cnt = 0
        self.record_node_cnt = 0
        self.chained_buffer_cnt = 0

    def __str__(self):
        return f"TableStatistics(name={self.name}, index_column={self.index_column}, buffer_count={self.buffer_count}, size={self.size}, interior_node_cnt={self.interior_node_cnt}, record_node_cnt={self.record_node_cnt}, chained_buffer_cnt={self.chained_buffer_cnt})"
```
Note that I've kept the same variable names and structure as the original Java code, but replaced `public` with nothing (since Python doesn't have a direct equivalent), and removed the comments since they are not necessary in Python.