class InsertTabletPlanGenerator:
    def __init__(self, target_device: str, tablet_row_limit: int):
        self.target_device = target_device
        self.query_data_set_indexes = []
        self.target_measurement_ids = []

        self.tablet_row_limit = tablet_row_limit

    def collect_target_path_information(self, target_measurement_id: str, query_data_set_index: int):
        self.target_measurement_ids.append(target_measurement_id)
        self.query_data_set_indexes.append(query_data_set_index)

    def internally_construct_new_plan(self):
        self.row_count = 0
        self.times = [0] * self.tablet_row_limit
        self.columns = [[] for _ in range(len(self.target_measurement_ids))]
        self.bit_maps = [BitMap(self.tablet_row_limit) for _ in range(len(self.target_measurement_ids))]

    def collect_row_record(self, row_record):
        if len(self.columns[0]) != len(row_record.get_fields()):
            initialized_data_type_indexes = try_set_data_types(row_record)
            try_init_columns(initialized_data_type_indexes)

        self.times[self.row_count] = row_record.get_timestamp()

        for i in range(len(self.target_measurement_ids)):
            field = row_record.get_fields()[self.query_data_set_indexes[i]]

            if field is None or field.get_data_type() is None:
                continue

            self.bit_maps[i].unmark(self.row_count)

            data_type = field.get_data_type()
            column_index = self.query_data_set_indexes[i]

            if data_type == 'BOOLEAN':
                self.columns[column_index][self.row_count] = field.get_bool_value()
            elif data_type == 'INT32':
                self.columns[column_index][self.row_count] = field.get_int_value()
            elif data_type == 'INT64':
                self.columns[column_index][self.row_count] = field.get_long_value()
            elif data_type == 'FLOAT':
                self.columns[column_index][self.row_count] = field.get_float_value()
            elif data_type == 'DOUBLE':
                self.columns[column_index][self.row_count] = field.get_double_value()
            elif data_type == 'TEXT':
                self.columns[column_index][self.row_count] = field.get_binary_value()

        self.row_count += 1

    def try_set_data_types(self, row_record):
        initialized_data_type_indexes = []
        fields = row_record.get_fields()

        for i in range(len(self.target_measurement_ids)):
            if len(initialized_data_type_indexes) == len(self.columns[0]):
                break

            query_data_set_index = self.query_data_set_indexes[i]

            if fields[query_data_set_index] is not None and fields[query_data_set_index].get_data_type() is not None:
                data_types[self.target_measurement_ids.index(fields[query_data_set_index])] = fields[query_data_set_index].get_data_type()
                initialized_data_type_indexes.append(i)

        for i in range(len(self.columns)):
            if self.data_types[i] is None and len(initialized_data_type_indexes) < len(self.columns):
                data_types[self.target_measurement_ids.index(fields[i])] = fields[i].get_data_type()
                initialized_data_type_indexes.append(i)

        return initialized_data_type_indexes

    def try_init_columns(self, initialized_data_type_indexes):
        for i in initialized_data_type_indexes:
            if self.data_types[i] == 'BOOLEAN':
                self.columns[i] = [False] * self.tablet_row_limit
            elif self.data_types[i] == 'INT32':
                self.columns[i] = [0] * self.tablet_row_limit
            elif self.data_types[i] == 'INT64':
                self.columns[i] = [0] * self.tablet_row_limit
            elif self.data_types[i] == 'FLOAT':
                self.columns[i] = [0.0] * self.tablet_row_limit
            elif self.data_types[i] == 'DOUBLE':
                self.columns[i] = [0.0] * self.tablet_row_limit
            elif self.data_types[i] == 'TEXT':
                self.columns[i] = [None] * self.tablet_row_limit

    def generate_insert_tablet_plan(self):
        non_empty_column_names = []

        count_of_non_empty_columns = 0
        for i in range(len(self.target_measurement_ids)):
            if len(non_empty_column_names) == count_of_non_empty_columns:
                break

            query_data_set_index = self.query_data_set_indexes[i]

            if self.columns[query_data_set_index] is None or self.bit_maps[query_data_set_index].is_all_unmarked():
                continue

            non_empty_column_names.append(self.target_measurement_ids[i])
            columns[count_of_non_empty_columns] = self.columns[query_data_set_index]
            bit_maps[count_of_non_empty_columns] = self.bit_maps[query_data_set_index]
            data_types[count_of_non_empty_columns] = self.data_types[i]

            count_of_non_empty_columns += 1

        insert_tablet_plan = InsertTabletPlan(PartialPath(self.target_device), non_empty_column_names)
        insert_tablet_plan.set_aligned(False)
        insert_tablet_plan.set_row_count(self.row_count)

        if len(non_empty_column_names) != len(self.columns):
            self.columns = columns[:count_of_non_empty_columns]
            self.bit_maps = bit_maps[:count_of_non_empty_columns]
            self.data_types = data_types[:count_of_non_empty_columns]

        if self.row_count != self.tablet_row_limit:
            times = [0] * self.row_count
            for i in range(len(self.columns)):
                switch (self.data_types[i]):
                    case 'BOOLEAN':
                        columns[i] = [False] * self.row_count
                    case 'INT32':
                        columns[i] = [0] * self.row_count
                    case 'INT64':
                        columns[i] = [0] * self.row_count
                    case 'FLOAT':
                        columns[i] = [0.0] * self.row_count
                    case 'DOUBLE':
                        columns[i] = [0.0] * self.row_count
                    case 'TEXT':
                        columns[i] = [None] * self.row_count

        insert_tablet_plan.set_times(times)
        insert_tablet_plan.set_columns(columns)
        insert_tablet_plan.set_bit_maps(bit_maps)
        insert_tablet_plan.set_data_types(data_types)

        return insert_tablet_plan
