class DataSetWithoutTimeGenerator:
    def __init__(self, paths, data_types, readers):
        self.readers = readers
        super().__init__(paths, data_types)

    def init_heap(self):
        self.has_data_remaining = []
        self.batch_data_list = []
        self.time_heap = []
        self.time_set = set()

        for i in range(len(paths)):
            reader = readers[i]
            if not reader.hasNextBatch():
                batch_data = BatchData()
                self.batch_data_list.append(batch_data)
                self.has_data_remaining.append(False)
            else:
                batch_data = reader.next_batch()
                self.batch_data_list.append(batch_data)
                self.has_data_remaining.append(True)

        for data in self.batch_data_list:
            if data.has_current():
                time_heap_put(data.current_time())

    def hasNext_without_constraint(self):
        return len(self.time_heap) > 0

    @staticmethod
    def put_value_to_field(col, field):
        if col.get_data_type() == 'BOOLEAN':
            field.set_bool_v(col.get_boolean())
        elif col.get_data_type() == 'INT32':
            field.set_int_v(col.get_int())
        elif col.get_data_type() == 'INT64':
            field.set_long_v(col.get_long())
        elif col.get_data_type() == 'FLOAT':
            field.set_float_v(col.get_float())
        elif col.get_data_type() == 'DOUBLE':
            field.set_double_v(col.get_double())
        elif col.get_data_type() == 'TEXT':
            field.set_binary_v(col.get_binary())
        else:
            raise UnSupportedDataTypeException("UnSupported" + col.get_data_type())

    def next_without_constraint(self):
        min_time = time_heap_get()
        record = RowRecord(min_time)

        for i in range(len(paths)):
            if not self.has_data_remaining[i]:
                record.add_field(None)
                continue

            data = self.batch_data_list[i]
            field = Field(data_types[i])

            if data.has_current() and data.current_time() == min_time:
                put_value_to_field(data, field)
                data.next()

                if not data.has_current():
                    reader = readers[i]
                    if reader.hasNextBatch():
                        data = reader.next_batch()
                        if data.has_current():
                            self.batch_data_list[i] = data
                            time_heap_put(data.current_time())
                    else:
                        self.has_data_remaining[i] = False
                else:
                    time_heap_put(data.current_time())

            record.add_field(field)

        return record

    def time_heap_put(self, time):
        if not time_set.contains(time):
            time_set.add(time)
            time_heap.append(time)

    @staticmethod
    def time_heap_get():
        t = time_heap.pop()
        time_set.remove(t)
        return t


class BatchData:
    pass  # implement the methods and attributes of this class as needed

class RowRecord:
    pass  # implement the methods and attributes of this class as needed

class Field:
    pass  # implement the methods and attributes of this class as needed
