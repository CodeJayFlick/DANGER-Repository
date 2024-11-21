class IoTDBNonAlignJDBCResultSet:
    def __init__(self,
                 statement,
                 column_name_list,
                 column_type_list,
                 column_name_index,
                 ignore_timestamp,
                 client,
                 sql,
                 query_id,
                 session_id,
                 dataset,
                 tracing_info,
                 timeout,
                 operation_type,
                 sg_columns,
                 alias_column_map):
        super(
            statement=statement,
            column_name_list=column_name_list,
            column_type_list=column_type_list,
            column_name_index=column_name_index,
            ignore_timestamp=ignore_timestamp,
            client=client,
            sql=sql,
            query_id=query_id,
            session_id=session_id,
            timeout=timeout,
            sg_columns=sg_columns,
            alias_column_map=alias_column_map
        )
        self.times = [bytes(Long.BYTES) for _ in range(len(column_name_list))]
        self.operation_type = operation_type
        self.sg_columns = sg_columns

    def get_long(self, column_name):
        if column_name.startswith(TIMESTAMP_STR):
            column = column_name[len(TIMESTAMP_STR):]
            index = self.column_ordinal_map[column] - START_INDEX
            if self.times[index]:
                return BytesUtils.bytes_to_long(self.times[index])
            else:
                return 0

    def fetch_results(self):
        req = TSFetchResultsReq(
            session_id=self.session_id,
            sql=self.sql,
            fetch_size=fetch_size,
            query_id=self.query_id,
            has_result_set=False
        )
        try:
            resp = self.client.fetch_results(req)
            RpcUtils.verify_success(resp.status)

            if not resp.has_result_set:
                self.empty_result_set = True
                close()
                return False

            self.ts_query_non_align_dataset = resp.non_align_query_data_set
            if self.ts_query_non_align_dataset is None:
                self.empty_result_set = True
                close()
                return False

        except TException as e:
            raise SQLException(
                "Cannot fetch result from server, because of network connection: {}".format(e)
            )

    def has_cached_results(self):
        return (self.ts_query_non_align_dataset and self.has_times_remaining())

    def has_times_remaining(self):
        for time in self.ts_query_non_align_dataset.time_list:
            if time.remaining() >= Long.BYTES:
                return True
        return False

    def construct_one_row(self):
        for i, _ in enumerate(self.ts_query_non_align_dataset.time_list):
            self.times[i] = None
            value_buffer = self.ts_query_non_align_dataset.value_list[i]
            data_type = self.column_type_deduplicated_list[i]

            if data_type == TSDataType.BOOLEAN:
                self.values[i] = bytes(1)
                value_buffer.get(self.values[i])
            elif data_type == TSDataType.INT32:
                self.values[i] = bytes(Integer.BYTES)
                value_buffer.get(self.values[i])
            elif data_type == TSDataType.INT64:
                self.values[i] = bytes(Long.BYTES)
                value_buffer.get(self.values[i])
            elif data_type == TSDataType.FLOAT:
                self.values[i] = bytes(Float.BYTES)
                value_buffer.get(self.values[i])
            elif data_type == TSDataType.DOUBLE:
                self.values[i] = bytes(Double.BYTES)
                value_buffer.get(self.values[i])
            elif data_type == TSDataType.TEXT:
                length = value_buffer.getInt()
                self.values[i] = ReadWriteIOUtils.read_bytes(value_buffer, length)

    def check_record(self):
        if not self.ts_query_non_align_dataset:
            raise SQLException("No record remains")

    def get_value_by_name(self, column_name):
        if column_name.startswith(TIMESTAMP_STR):
            column = column_name[len(TIMESTAMP_STR):]
            index = self.column_ordinal_map[column] - START_INDEX
            if self.times[index]:
                return str(BytesUtils.bytes_to_long(self.times[index]))
            else:
                return None

    def get_object_by_name(self, column_name):
        check_record()
        if column_name.startswith(TIMESTAMP_STR):
            column = column_name[len(TIMESTAMP_STR):]
            index = self.column_ordinal_map[column] - START_INDEX
            if self.times[index]:
                return BytesUtils.bytes_to_long(self.times[index])
            else:
                return None

    def get_operation_type(self):
        return self.operation_type

    def get_sg_columns(self):
        return self.sg_columns


class IoTDBTracingInfo:
    pass


def main():
    # Your code here
    pass


if __name__ == "__main__":
    main()
