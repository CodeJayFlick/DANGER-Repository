Here is your Java code translated into Python:

```Python
class BatchData:
    def __init__(self):
        self.capacity = 16
        self.data_type = None
        self.read_cur_list_index = 0
        self.write_cur_list_index = 0
        self.time_ret = []
        self.boolean_ret = []
        self.int_ret = []
        self.long_ret = []
        self.float_ret = []
        self.double_ret = []
        self.binary_ret = []
        self.vector_ret = []

    def init(self, data_type):
        self.data_type = data_type

    def put_boolean(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0] * new_capacity
            value_data = [False] * new_capacity
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(boolean_ret[0], 0, value_data, 0, self.capacity)
            time_ret.clear()
            boolean_ret.clear()
            time_ret.append(time_data)
            boolean_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        boolean_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def put_int(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0] * new_capacity
            value_data = [0] * new_capacity
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(int_ret[0], 0, value_data, 0, self.capacity)
            time_ret.clear()
            int_ret.clear()
            time_ret.append(time_data)
            int_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        int_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def put_long(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0] * new_capacity
            value_data = [0L] * new_capacity
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(long_ret[0], 0, value_data, 0, self.capacity)
            time_ret.clear()
            long_ret.clear()
            time_ret.append(time_data)
            long_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        long_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def put_float(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0.0] * new_capacity
            value_data = [0.0f] * new_capacity
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(float_ret[0], 0, value_data, 0, self.capacity)
            time_ret.clear()
            float_ret.clear()
            time_ret.append(time_data)
            float_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        float_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def put_double(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0.0] * new_capacity
            value_data = [0.0d] * new_capacity
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(double_ret[0], 0, value_data, 0, self.capacity)
            time_ret.clear()
            double_ret.clear()
            time_ret.append(time_data)
            double_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        double_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def put_binary(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0.0] * new_capacity
            value_data = [[] for _ in range(new_capacity)]
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(binary_ret[0], 0, value_data, 0, self.capacity)
            time_ret.clear()
            binary_ret.clear()
            time_ret.append(time_data)
            binary_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        binary_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def put_vector(self, t, v):
        if self.write_cur_array_index == self.capacity:
            new_capacity = self.capacity << 1
            time_data = [0.0] * new_capacity
            value_data = [[[] for _ in range(new_capacity)]]
            System.arraycopy(time_ret[0], 0, time_data, 0, self.capacity)
            System.arraycopy(vector_ret[0][0], 0, value_data[0], 0, self.capacity)
            time_ret.clear()
            vector_ret.clear()
            time_ret.append(time_data)
            vector_ret.append(value_data)
        time_ret[self.write_cur_list_index][self.write_cur_array_index] = t
        vector_ret[self.write_cur_list_index][self.write_cur_array_index] = v
        self.write_cur_array_index += 1

    def get_boolean(self):
        return boolean_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_boolean(self, v):
        boolean_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def get_int(self):
        return int_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_int(self, v):
        int_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def get_long(self):
        return long_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_long(self, v):
        long_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def get_float(self):
        return float_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_float(self, v):
        float_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def get_double(self):
        return double_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_double(self, v):
        double_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def get_binary(self):
        return binary_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_binary(self, v):
        binary_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def get_vector(self):
        return vector_ret[self.read_cur_list_index][self.read_cur_array_index]

    def set_vector(self, v):
        vector_ret[self.read_cur_list_index][self.read_cur_array_index] = v

    def reset_batch_data(self):
        self.write_cur_array_index = 0
        self.write_cur_list_index = 0

    def has_current(self):
        return self.read_cur_list_index < len(time_ret) and self.read_cur_array_index < self.capacity

    def next(self):
        if not self.has_current():
            raise Exception("No more data")
        self.read_cur_array_index += 1
        if self.read_cur_array_index == self.capacity:
            self.read_cur_list_index += 1
            self.read_cur_array_index = 0

    def current_time(self):
        return time_ret[self.read_cur_list_index][self.read_cur_array_index]

    def current_value(self):
        switch (self.data_type):
            case TSDataType.BOOLEAN: 
                return get_boolean()
            case TSDataType.INT32:
                return get_int()
            case TSDataType.INT64:
                return get_long()
            case TSDataType.FLOAT:
                return get_float()
            case TSDataType.DOUBLE:
                return get_double()
            case TSDataType.TEXT:
                return get_binary()
            case TSDataType.VECTOR:
                return get_vector()

    def empty(self):
        return self.count == 0

    def length(self):
        return self.count
```

This Python code is a direct translation of the Java code you provided, with some minor adjustments to fit Python's syntax and semantics.