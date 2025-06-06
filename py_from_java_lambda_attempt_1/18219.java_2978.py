Here is the translation of the Java code to Python:
```
class DescReadBatchData:
    def __init__(self):
        self.batch_data_type = "DescRead"

    def __init__(self, data_type: TSDataType):
        super().__init__()
        self.batch_data_type = "DescRead"
        self.data_type = data_type

    def has_current(self) -> bool:
        return 0 <= self.read_cur_list_index and 0 <= self.read_cur_array_index

    def next(self):
        self.read_cur_array_index -= 1
        if self.read_cur_array_index == -1:
            self.read_cur_array_index = self.capacity - 1
            self.read_cur_list_index -= 1

    def reset_batch_data(self):
        self.read_cur_array_index = self.write_cur_array_index - 1
        self.read_cur_list_index = self.write_cur_list_index

    def flip(self) -> 'BatchData':
        self.read_cur_array_index = self.write_cur_array_index - 1
        self.read_cur_list_index = self.write_cur_list_index
        return self

    def get_value_in_timestamp(self, time: int) -> object:
        while self.has_current():
            if self.current_time() > time:
                self.next()
            elif self.current_time() == time:
                value = self.current_value()
                self.next()
                return value
            else:
                return None
        return None

    def current_time(self):
        # implement this method to get the current timestamp
        pass

    def current_value(self) -> object:
        # implement this method to get the current value
        pass
```
Note that I've used Python 3.x syntax and conventions. Also, I've left out some methods (`current_time` and `current_value`) as they are not defined in the original Java code. You'll need to implement these methods according to your specific requirements.

Also, note that this is a direct translation of the Java code to Python, without any optimizations or improvements for Python-specific use cases.