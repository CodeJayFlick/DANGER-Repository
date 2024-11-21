import os
from typing import List

class IoTDBTest:
    def __init__(self):
        self.plan_executor = None
        self.prev_enable_auto_schema = False
        self.prev_use_async_server = False

    @staticmethod
    def prepare_schema():
        for i in range(4):
            set_storage_group(f"test_sg_{i}")
            for j in range(10):
                create_time_series(i, j)

        set_storage_group("test_sg_4")

        for i in range(5, 10):
            set_storage_group(f"test_sg_{i}")

    def prepare_data(self, sg_num: int, time_offset: int, size: int) -> None:
        insert_plan = InsertRowPlan()
        insert_plan.set_prefix_path(PartialPath(f"test_sg_{sg_num}"))
        measurements = [f"measurement_{i}" for i in range(10)]
        schemas = [get_test_measurement_mnode(i) for i in range(10)]

        insert_plan.set_measurements(measurements)
        insert_plan.set_need_infer_type(True)

        values = []
        for _ in range(size):
            time_value = os.getpid()
            values.extend([str(time_value * 1.0)] * len(measurements))
            insert_plan.set_time(time_offset + size - 1)
            insert_plan.set_values(values)
            insert_plan.set_measurement_mnodes(schemas)

    def set_storage_group(self, storage_group_name: str) -> None:
        try:
            self.plan_executor.set_storage_group(SetStorageGroupPlan(PartialPath(storage_group_name)))
        except (QueryProcessException, IllegalPathException):
            pass

    @staticmethod
    def create_time_series(sg_num: int, series_num: int) -> None:
        schema = get_test_measurement_schema(series_num)
        self.plan_executor.process_non_query(CreateTimeSeriesPlan(
            PartialPath(f"test_sg_{sg_num}{IoTDBConstant.PATH_SEPARATOR}{schema.get_measurement_id()}"),
            schema.get_type(),
            schema.get_encoding_type(),
            schema.get_compressor(),
            schema.get_props(),
            {},
            {}
        ))

    def query(self, path_strs: List[str], expression: IExpression) -> QueryDataSet:
        context = QueryContext(QueryResourceManager.getInstance().assign_query_id(True))
        query_plan = RawDataQueryPlan()
        query_plan.set_expression(expression)
        paths = [PartialPath(path_str) for path_str in path_strs]
        query_plan.set_deduplicated_paths_and_update(paths)

    def __del__(self):
        if self.plan_executor:
            try:
                self.plan_executor.close()
            except (IOException, StorageEngineException):
                pass
