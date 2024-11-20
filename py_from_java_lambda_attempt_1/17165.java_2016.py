Here is the translation of the Java code into Python:

```Python
class FlatMeasurementSchemaCollector:
    def __init__(self, start_node: 'IMNode', path: 'PartialPath'):
        self.result_set = []
        super().__init__(start_node, path)

    def set_need_last(self, need_last):
        self.need_last = need_last

    def set_query_context(self, query_context):
        self.query_context = query_context

    def collect_unary_measurement(self, node: 'UnaryMeasurementMNode'):
        measurement_schema = node.get_schema()
        ts_row = [node.alias,
                   str(node.get_storage_group_path().get_full_path()),
                   str(measurement_schema.type),
                   str(measurement_schema.encoding_type),
                   str(measurement_schema.compressor),
                   str(node.offset)]
        if self.need_last:
            ts_row.append(str(get_last_timestamp(node, query_context)))
        else:
            ts_row.append(None)
        temp = {'path': node.get_partial_path(), 'ts_row': tuple(ts_row)}
        self.result_set.append(temp)

    def collect_multi_measurement_component(self, node: 'MultiMeasurementMNode', index):
        schema = node.get_schema()
        measurements = list(schema.get_sub_measurements_list())
        ts_row = [None,
                  str(node.get_storage_group_path().get_full_path()),
                  str(schema.get_sub_measurements_ts_data_type_list()[index]),
                  str(schema.get_sub_measurements_ts_encoding_list()[index]),
                  str(schema.compressor),
                  '-1']
        if self.need_last:
            ts_row.append(str(get_last_timestamp(node, query_context)))
        else:
            ts_row.append(None)
        temp = {'path': VectorPartialPath(node.get_full_path(), measurements[index]), 'ts_row': tuple(ts_row)}
        self.result_set.append(temp)

    def get_storage_group_path(self, node: 'IMeasurementMNode'):
        if node is None:
            return None
        temp = node
        while temp != None and not isinstance(temp, StorageGroup):
            temp = temp.get_parent()
        if temp == None or not isinstance(temp, StorageGroup):
            raise StorageGroupNotSetException(node.get_full_path())
        return temp.get_partial_path()

def get_last_timestamp(node: 'IMeasurementMNode', query_context):
    # This function is not implemented in the original Java code
    pass

class VectorPartialPath:
    def __init__(self, full_path, measurement):
        self.full_path = full_path
        self.measurement = measurement

class StorageGroupNotSetException(Exception):
    pass
```

Please note that I have translated the given Java code into Python. However, some parts of the original code (like `getLastTimeStamp` function) are not implemented in this translation as they were missing from your provided Java code.