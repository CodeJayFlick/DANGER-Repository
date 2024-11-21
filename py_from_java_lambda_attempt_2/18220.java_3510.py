Here is the translation of the Java code into Python:

```Python
class DescReadWriteBatchData:
    def __init__(self, data_type):
        self.batch_data_type = "DescReadWrite"
        self.data_type = data_type
        self.read_cur_list_index = 0
        self.write_cur_array_index = -1

        if data_type == 'BOOLEAN':
            self.time_ret = []
            self.boolean_ret = []
        elif data_type == 'INT32' or data_type == 'INT64':
            self.time_ret = []
            self.int_ret = []
        elif data_type == 'FLOAT' or data_type == 'DOUBLE':
            self.time_ret = []
            self.float_ret = []
        elif data_type == 'TEXT':
            self.time_ret = []
            self.binary_ret = []
        elif data_type == 'VECTOR':
            self.time_ret = []
            self.vector_ret = []

    def put_boolean(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.boolean_ret.insert(0, [False] * capacity)
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.boolean_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def put_int(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.int_ret.insert(0, [0] * capacity)
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.int_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def put_long(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.long_ret.insert(0, [0L] * capacity)
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.long_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def put_float(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.float_ret.insert(0, [0.0] * capacity)
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.float_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def put_double(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.double_ret.insert(0, [0.0] * capacity)
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.double_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def put_binary(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.binary_ret.insert(0, [None] * capacity)
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.binary_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def put_vector(self, t, v):
        if self.write_cur_array_index == -1:
            if len(self.time_ret) >= CAPACITY_THRESHOLD:
                self.time_ret.insert(0, [capacity] * capacity)
                self.vector_ret.insert(0, [[None for _ in range(capacity)] for _ in range(capacity)])
                self.write_cur_list_index += 1
                self.write_cur_array_index = capacity - 1

        self.time_ret[0][self.write_cur_array_index] = t
        self.vector_ret[0][self.write_cur_array_index] = v

        self.write_cur_array_index -= 1
        self.count += 1

    def has_current(self):
        return (self.read_cur_list_index == 0 and self.read_cur_array_index > self.write_cur_array_index) or \
               (self.read_cur_list_index > 0 and self.read_cur_array_index >= 0)

    def next(self):
        super().read_cur_array_index -= 1
        if ((self.read_cur_list_index == 0 and self.read_cur_array_index <= self.write_cur_array_index) or 
            self.read_cur_array_index == -1):
            super().read_cur_list_index -= 1
            super().read_cur_array_index = capacity - 1

    def reset_batch_data(self):
        super().read_cur_array_index = capacity - 1
        super().read_cur_list_index = self.write_cur_list_index

    def get_time_by_index(self, idx):
        return self.time_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def get_long_by_index(self, idx):
        return self.long_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def get_double_by_index(self, idx):
        return self.double_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def get_int_by_index(self, idx):
        return self.int_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def get_float_by_index(self, idx):
        return self.float_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def get_binary_by_index(self, idx):
        return self.binary_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def get_boolean_by_index(self, idx):
        return self.boolean_ret[(idx + self.write_cur_array_index + 1) // capacity][(idx + self.write_cur_array_index + 1) % capacity]

    def flip(self):
        super().read_cur_array_index = capacity - 1
        super().read_cur_list_index = self.write_cur_list_index
        return self

CAPACITY_THRESHOLD = 1024