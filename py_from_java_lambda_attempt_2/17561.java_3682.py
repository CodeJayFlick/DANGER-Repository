Here is the translation of the Java code into Python:

```Python
class LayerCacheUtils:
    def __init__(self):
        pass

    @staticmethod
    def cache_points(data_type, source, target, point_number):
        count = 0
        while count < point_number and LayerCacheUtils.cache_point(data_type, source, target):
            count += 1
        return count

    @staticmethod
    def cache_point(data_type, source, target):
        if not source.next():
            return False

        if data_type == 'INT32':
            target.put_int(source.current_time(), source.current_int())
        elif data_type == 'INT64':
            target.put_long(source.current_time(), source.current_long())
        elif data_type == 'FLOAT':
            target.put_float(source.current_time(), source.current_float())
        elif data_type == 'DOUBLE':
            target.put_double(source.current_time(), source.current_double())
        elif data_type == 'BOOLEAN':
            target.put_boolean(source.current_time(), source.current_boolean())
        elif data_type == 'TEXT':
            target.put_binary(source.current_time(), source.current_binary())
        else:
            raise UnsupportedOperationException(data_type)

        source.ready_for_next()
        return True

    @staticmethod
    def cache_rows(source, target, rows_number):
        count = 0
        while count < rows_number and LayerCacheUtils.cache_row(source, target):
            count += 1
        return count

    @staticmethod
    def cache_row(source, target):
        if source.has_next_row_in_objects():
            target.put(source.next_row_in_objects())
            return True
        else:
            return False


# Example usage:

class UDFInputDataSet:
    def __init__(self):
        pass

    def has_next_row_in_objects(self):
        # implement this method as per your requirement
        pass

    def next_row_in_objects(self):
        # implement this method as per your requirement
        pass

class ElasticSerializableRowRecordList:
    def put(self, row_record_list):
        # implement this method as per your requirement
        pass


# Example usage:

udf_input_data_set = UDFInputDataSet()
elastic_serializable_row_record_list = ElasticSerializableRowRecordList()

LayerCacheUtils.cache_rows(udf_input_data_set, elastic_serializable_row_record_list, 10)
```

Please note that this translation is not a direct conversion from Java to Python. The original code has been modified and simplified for better readability in the context of Python programming language.