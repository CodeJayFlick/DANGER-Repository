class SessionDataSet:
    def __init__(self,
                 sql: str,
                 column_name_list: list[str],
                 column_type_list: list[any],
                 column_name_index: dict[str, int],
                 query_id: int,
                 statement_id: int,
                 client: any,
                 session_id: int,
                 query_data_set: any,
                 ignore_timestamp: bool = False,
                 timeout: int | None = None):
        self.io_tdb_rpc_data_set = IoTDBRpcDataSet(
            sql, column_name_list, column_type_list, column_name_index,
            ignore_timestamp, query_id, statement_id, client, session_id,
            query_data_set, Config.DEFAULT_FETCH_SIZE, timeout)

    @property
    def fetch_size(self) -> int:
        return self.io_tdb_rpc_data_set.fetch_size

    @fetch_size.setter
    def fetch_size(self, value: int):
        self.io_tdb_rpc_data_set.fetch_size = value

    @property
    def column_names(self) -> list[str]:
        return [column_name for column_name in self.io_tdb_rpc_data_set.column_name_list]

    @property
    def column_types(self) -> list[any]:
        return [column_type for column_type in self.io_tdb_rpc_data_set.column_type_list]

    def has_next(self) -> bool:
        try:
            return self.io_tdb_rpc_data_set.next()
        except (StatementExecutionException, IoTDBConnectionException):
            pass
        return False

    def construct_row_record_from_value_array(self) -> RowRecord | None:
        out_fields = []
        for i in range(len(self.io_tdb_rpc_data_set.column_type_list)):
            field = Field()

            index = i + 1
            dataset_column_index = i + START_INDEX
            if self.io_tdb_rpc_data_set.ignore_timestamp:
                index -= 1
                dataset_column_index -= 1

            loc = (
                self.io_tdb_rpc_data_set.column_ordinal_map.get(
                    self.io_tdb_rpc_data_set.column_name_list[index]
                ) - START_INDEX
            )

            if not self.io_tdb_rpc_data_set.is_null(dataset_column_index):
                value_bytes = self.io_tdb_rpc_data_set.values[loc]
                data_type = self.io_tdb_rpc_data_set.column_type_deduplicated_list[loc]

                switcher = {
                    TSDataType.BOOLEAN: lambda x: (BytesUtils.bytes_to_bool(value_bytes),),
                    TSDataType.INT32: lambda x: (BytesUtils.bytes_to_int(value_bytes),),
                    TSDataType.INT64: lambda x: (BytesUtils.bytes_to_long(value_bytes),),
                    TSDataType.FLOAT: lambda x: (BytesUtils.bytes_to_float(value_bytes),),
                    TSDataType.DOUBLE: lambda x: (BytesUtils.bytes_to_double(value_bytes),),
                    TSDataType.TEXT: lambda x: (Binary(new Binary(value_bytes)),)
                }

                try:
                    value = switcher[data_type]()
                    field.set_value(*value)
                except KeyError as e:
                    raise UnSupportedDataTypeException(
                        f"Data type {data_type} is not supported."
                    )

            else:
                field.set_null()

            out_fields.append(field)

        return RowRecord(BytesUtils.bytes_to_long(self.io_tdb_rpc_data_set.time), out_fields) if len(out_fields) > 0 else None

    def next(self) -> RowRecord | None:
        if not self.io_tdb_rpc_data_set.has_cached_record and not has_next():
            return None
        self.io_tdb_rpc_data_set.has_cached_record = False
        return construct_row_record_from_value_array()

    def close_operation_handle(self):
        try:
            self.io_tdb_rpc_data_set.close()
        except TException as e:
            raise IoTDBConnectionException(e.message)

class DataIterator:
    def __init__(self, session_data_set: SessionDataSet):
        self.session_data_set = session_data_set

    def next(self) -> bool:
        return self.session_data_set.next()

    def is_null(self, column_index: int | str) -> bool:
        if isinstance(column_index, int):
            return self.session_data_set.is_null(column_index)
        else:
            return self.session_data_set.is_null(column_index)

    def get_boolean(self, column_index: int | str) -> bool:
        if isinstance(column_index, int):
            return self.session_data_set.get_boolean(column_index)
        else:
            return self.session_data_set.get_boolean(column_index)

    # ... similar methods for other data types ...

class RowRecord:
    def __init__(self, time: int, out_fields: list[Field]):
        self.time = time
        self.out_fields = out_fields

# Other classes and functions are not shown here.
