class UDTFSelectK:
    def __init__(self):
        self.k = None
        self.data_type = None
        self.int_pq = []
        self.long_pq = []
        self.float_pq = []
        self.double_pq = []
        self.string_pq = []

    def validate(self, validator):
        try:
            validator.validate_input_series_number(1)
            validator.validate_input_series_data_type(
                0,
                'INT32',
                'INT64',
                'FLOAT',
                'DOUBLE',
                'TEXT'
            )
            validator.require_attribute('k')
            k = int(validator.get_parameters().get('k'))
            if not (0 < k <= 1000):
                raise ValueError("k has to be greater than 0 and less than or equal to 1000.")
        except Exception as e:
            raise UDFException(str(e))

    def before_start(self, parameters, configurations):
        self.k = int(parameters.get('k'))
        self.data_type = parameters.get_data_type(0)
        self.construct_pq()
        configurations.set_access_strategy(RowByRowAccessStrategy())
        configurations.set_output_data_type(self.data_type)

    def construct_pq(self):
        # This method should be implemented in the subclass
        pass

    def transform(self, row, collector):
        if self.data_type == 'INT32':
            self.transform_int(row.get_time(), row.get_int(0))
        elif self.data_type == 'INT64':
            self.transform_long(row.get_time(), row.get_long(0))
        elif self.data_type == 'FLOAT':
            self.transform_float(row.get_time(), row.get_float(0))
        elif self.data_type == 'DOUBLE':
            self.transform_double(row.get_time(), row.get_double(0))
        elif self.data_type == 'TEXT':
            self.transform_string(row.get_time(), row.get_string(0))

    def transform_int(self, time, value):
        # This method should be implemented in the subclass
        pass

    def transform_long(self, time, value):
        # This method should be implemented in the subclass
        pass

    def transform_float(self, time, value):
        # This method should be implemented in the subclass
        pass

    def transform_double(self, time, value):
        # This method should be implemented in the subclass
        pass

    def transform_string(self, time, value):
        # This method should be implemented in the subclass
        pass

    def terminate(self, collector):
        if self.data_type == 'INT32':
            for pair in sorted(self.int_pq, key=lambda x: x[0]):
                collector.put_int(pair[0], pair[1])
        elif self.data_type == 'INT64':
            for pair in sorted(self.long_pq, key=lambda x: x[0]):
                collector.put_long(pair[0], pair[1])
        elif self.data_type == 'FLOAT':
            for pair in sorted(self.float_pq, key=lambda x: x[0]):
                collector.put_float(pair[0], pair[1])
        elif self.data_type == 'DOUBLE':
            for pair in sorted(self.double_pq, key=lambda x: x[0]):
                collector.put_double(pair[0], pair[1])
        elif self.data_type == 'TEXT':
            for pair in sorted(self.string_pq, key=lambda x: x[0]):
                collector.put_string(pair[0], pair[1])

class UDFException(Exception):
    pass

class Row:
    def get_time(self):
        # This method should be implemented
        pass

    def get_int(self, index):
        # This method should be implemented
        pass

    def get_long(self, index):
        # This method should be implemented
        pass

    def get_float(self, index):
        # This method should be implemented
        pass

    def get_double(self, index):
        # This method should be implemented
        pass

    def get_string(self, index):
        # This method should be implemented
        pass


class PointCollector:
    def put_int(self, time, value):
        # This method should be implemented
        pass

    def put_long(self, time, value):
        # This method should be implemented
        pass

    def put_float(self, time, value):
        # This method should be implemented
        pass

    def put_double(self, time, value):
        # This method should be implemented
        pass

    def put_string(self, time, value):
        # This method should be implemented
        pass


class RowByRowAccessStrategy:
    pass
