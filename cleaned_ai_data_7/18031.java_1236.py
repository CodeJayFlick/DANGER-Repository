class IoTDBRpcDataSet:
    TIMESTAMP_STR = "Time"
    VALUE_IS_NULL = "The value got by %s (column name) is NULL."
    START_INDEX = 2

    def __init__(self, sql, column_name_list, column_type_list, column_name_index, ignore_timestamp, query_id, statement_id, client, session_id, query_data_set, fetch_size, timeout):
        self.session_id = session_id
        self.statement_id = statement_id
        self.ignore_timestamp = ignore_timestamp
        self.sql = sql
        self.query_id = query_id
        self.client = client
        self.fetch_size = fetch_size
        self.timeout = timeout

        column_size = len(column_name_list)
        self.column_names = []
        self.column_types = []

        if not ignore_timestamp:
            self.column_names.append(TIMESTAMP_STR)
            self.column_types.append(TSDataType.INT64)

        for i in range(len(column_name_index)):
            name = column_name_list[i]
            self.column_names.append(name)
            self.column_types.append(column_type_list[i])

        time = bytearray(Long.BYTES)
        current_bitmap = bytearray(len(self.column_types))
        values = [bytearray() if t == TSDataType.TEXT else bytearray(type_size) for type_size, t in zip([Integer.BYTES, Long.BYTES, Float.BYTES, Double.BYTES] + [(0,) * len(column_type_list)], column_types)]

    def close(self):
        if self.is_closed:
            return
        try:
            req = TSCloseOperationReq(session_id=self.session_id)
            req.set_statement_id(self.statement_id)
            req.set_query_id(self.query_id)
            resp = client.close_operation(req)
            RpcUtils.verify_success(resp.status)
        except (StatementExecutionException, TException) as e:
            raise IoTDBConnectionException("Cannot close dataset because of network connection: {}".format(e))

    def next(self):
        if self.has_cached_results():
            construct_one_row()
            return True
        elif not self.empty_result_set:
            try:
                fetch_results()
                construct_one_row()
                return True
            except (StatementExecutionException, IoTDBConnectionException) as e:
                close()
                raise IoTDBConnectionException("Cannot close dataset because of network connection: {}".format(e))
        else:
            close()
            return False

    def has_cached_results(self):
        return self.ts_query_data_set is not None and self.ts_query_data_set.time.has_remaining()

    def construct_one_row(self):
        for i in range(len(self.column_types)):
            if not is_null(i, self.rows_index - 1):
                values[i] = ts_query_data_set.value_list.get(i)
            else:
                last_read_was_null = True
                break

        self.rows_index += 1
        has_cached_record = True

    def is_null(self, column_index):
        if column_index < 0 or column_index >= len(values) or not values[column_index].has_remaining():
            return False
        else:
            return True

    # getters for different data types
    def get_boolean(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return False
        else:
            last_read_was_null = False
            return bytes_to_bool(values[index])

    def get_double(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return 0.0
        else:
            last_read_was_null = False
            return bytes_to_double(values[index])

    def get_float(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return 0.0
        else:
            last_read_was_null = False
            return bytes_to_float(values[index])

    def get_int(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return 0
        else:
            last_read_was_null = False
            return bytes_to_int(values[index])

    def get_long(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return 0L
        else:
            last_read_was_null = False
            return bytes_to_long(values[index])

    def get_object(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return None
        else:
            last_read_was_null = False
            return bytes_to_long(values[index])

    def get_string(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return None
        else:
            last_read_was_null = False
            return str(values[index], 'utf-8')

    def get_timestamp(self, column_name):
        check_record()
        index = self.column_names.index(column_name)
        if is_null(index, self.rows_index - 1):
            last_read_was_null = True
            return None
        else:
            last_read_was_null = False
            return Timestamp(bytes_to_long(values[index]))

    def fetch_results(self):
        rows_index = 0
        req = TSFetchResultsReq(session_id=self.session_id, sql=self.sql, fetch_size=self.fetch_size, query_id=self.query_id, timeout=self.timeout)
        try:
            resp = client.fetch_results(req)
            RpcUtils.verify_success(resp.status)
            self.ts_query_data_set = resp.query_data_set
            return resp.has_result_set
        except (StatementExecutionException, TException) as e:
            raise IoTDBConnectionException("Cannot fetch result from server because of network connection: {}".format(e))

    def set_ts_query_data_set(self, ts_query_data_set):
        self.ts_query_data_set = ts_query_data_set
        self.empty_result_set = ts_query_data_set is None or not ts_query_data_set.time.has_remaining()
