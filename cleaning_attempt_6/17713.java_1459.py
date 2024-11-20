class EvictableBatchList:
    def __init__(self, data_type):
        self.data_type = data_type
        self.batch_list = []
        self.size = 0
        self.actual_outer_index_at_0 = 0

    def put_int(self, t, v):
        if self.size % internal_batch_size == 0:
            self.batch_list.append(BatchData(self.data_type))
        self.batch_list[self.size // internal_batch_size - self.actual_outer_index_at_0].put_int(t, v)
        self.size += 1

    def put_long(self, t, v):
        if self.size % internal_batch_size == 0:
            self.batch_list.append(BatchData(self.data_type))
        self.batch_list[self.size // internal_batch_size - self.actual_outer_index_at_0].put_long(t, v)
        self.size += 1

    def put_float(self, t, v):
        if self.size % internal_batch_size == 0:
            self.batch_list.append(BatchData(self.data_type))
        self.batch_list[self.size // internal_batch_size - self.actual_outer_index_at_0].put_float(t, v)
        self.size += 1

    def put_double(self, t, v):
        if self.size % internal_batch_size == 0:
            self.batch_list.append(BatchData(self.data_type))
        self.batch_list[self.size // internal_batch_size - self.actual_outer_index_at_0].put_double(t, v)
        self.size += 1

    def put_boolean(self, t, v):
        if self.size % internal_batch_size == 0:
            self.batch_list.append(BatchData(self.data_type))
        self.batch_list[self.size // internal_batch_size - self.actual_outer_index_at_0].put_boolean(t, v)
        self.size += 1

    def put_binary(self, t, v):
        if self.size % internal_batch_size == 0:
            self.batch_list.append(BatchData(self.data_type))
        self.batch_list[self.size // internal_batch_size - self.actual_outer_index_at_0].put_binary(t, v)
        self.size += 1

    def get_time_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_time_by_index(index % internal_batch_size)

    def get_int_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_int_by_index(index % internal_batch_size)

    def get_long_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_long_by_index(index % internal_batch_size)

    def get_float_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_float_by_index(index % internal_batch_size)

    def get_double_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_double_by_index(index % internal_batch_size)

    def get_boolean_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_boolean_by_index(index % internal_batch_size)

    def get_binary_by_index(self, index):
        return self.batch_list[index // internal_batch_size - self.actual_outer_index_at_0].get_binary_by_index(index % internal_batch_size)

    def set_eviction_upper_bound(self, eviction_upper_bound):
        outer_eviction_upper_bound = eviction_upper_bound // internal_batch_size
        if self.actual_outer_index_at_0 < outer_eviction_upper_bound:
            do_eviction(outer_eviction_upper_bound)
        return

    def do_eviction(self, outer_eviction_upper_bound):
        self.batch_list = list(self.batch_list[outer_eviction_upper_bound - self.actual_outer_index_at_0:])
        self.actual_outer_index_at_0 = outer_eviction_upper_bound
        return

    def size(self):
        return self.size

    def get_data_type(self):
        return self.data_type


class BatchData:
    def __init__(self, data_type):
        self.data_type = data_type

    # implement put_int, put_long, put_float, put_double, put_boolean, and put_binary methods
    pass


internal_batch_size = 1024 ** 2  # or any other value you want to set for internal batch size


# Example usage:
data_type = TSDataType.INT64
batch_list = EvictableBatchList(data_type)

for i in range(10000):
    if i % internal_batch_size == 0:
        batch_list.put_int(i, i)
    else:
        batch_list.batch_list[0].put_int(i, i)

print(batch_list.size())
