Here is the translation of the Java code into Python:

```Python
import os
from datetime import zoneinfo

class PlannerTest:
    def __init__(self):
        self.compression_type = TSFileDescriptor().get_config().get_compressor()
        self.m_manager = IoTDB.metaManager
        self.processor = Planner()

    @staticmethod
    def setup():
        IoTDB.metaManager.init()
        EnvironmentUtils.envSetUp()
        m_manager.set_storage_group(PartialPath("root.vehicle"))
        m_manager.set_storage_group(PartialPath("root.vehicle1"))
        for i in range(12):
            path = PartialPath(f"root.{i}.device{i}.sensor{i}")
            m_manager.create_timeseries(path, TSDataType.valueOf("INT32"), TSEncoding.valueOf("RLE"),
                                         self.compression_type, Collections.empty_map())

    @staticmethod
    def teardown():
        EnvironmentUtils.clean_env()

    def test_parse_sql_to_physical_plan(self):
        create_sg_statement = "set storage group to root.vehicle"
        plan1 = processor.parse_sql_to_physical_plan(create_sg_statement)
        assert plan1.get_operator_type() == OperatorType.SET_STORAGE_GROUP

        create_ts_statement1 = f"create timeseries root.{i}.device{i}.sensor{i} with datatype=INT32,encoding=RLE"
        for i in range(12):
            path = PartialPath(f"root.{i}.device{i}.sensor{i}")
            plan2 = processor.parse_sql_to_physical_plan(create_ts_statement1)
            assert plan2.get_operator_type() == OperatorType.CREATE_TIMESERIES

    def test_parse_show_child_node_to_physical_plan(self):
        show_child_nodes_statement = "show child nodes root.vehicle1.device1"
        plan14 = processor.parse_sql_to_physical_plan(show_child_nodes_statement)
        assert plan14.get_operator_type() == OperatorType.SHOW

    def test_parse_error_sql_to_physical_plan(self):
        create_ts_statement = f"create timeseriess root.{i}.device{i}.sensor{i} with datatype=INT32,encoding=RLE"
        try:
            processor.parse_sql_to_physical_plan(create_ts_statement)
        except ParseCancellationException as e:
            assert str(e) == "the measurementList's size 2 is not consistent with the valueList's size 1"

    def test_insert_statement_with_null_value(self):
        create_ts_statement = f"insert into root.{i}.device{i}(time,s0) values(10,NaN)"
        physical_plan = processor.parse_sql_to_physical_plan(create_ts_statement)
        assert isinstance(physical_plan, InsertRowPlan)
        assert "NaN" == str((InsertRowPlan).get_values()[0])

    def test_raw_data_query_req_to_physical_plan_test(self):
        ts_raw_data_query_req = TSRawDataQueryReq()
        paths = [f"root.{i}.device{i}.sensor{i}" for i in range(2)]
        ts_raw_data_query_req.set_paths(paths)
        ts_raw_data_query_req.set_start_time(0)
        ts_raw_data_query_req.set_end_time(100)
        ts_raw_data_query_req.set_fetch_size(1000)
        physical_plan = processor.raw_data_query_req_to_physical_plan(ts_raw_data_query_req, zoneinfo("Asia/Shanghai"))
        assert plan14.get_operator_type() == OperatorType.QUERY
        for i in range(len(paths)):
            path = paths[i]
            assert f"root.{i}.device{i}.sensor{i}" == physical_plan.get_paths()[i].get_full_path()

    def test_last_data_query_req_to_physical_plan_test(self):
        ts_last_data_query_req = TSLastDataQueryReq()
        paths = [f"root.{i}.device{i}.sensor{i}" for i in range(1)]
        ts_last_data_query_req.set_paths(paths)
        ts_last_data_query_req.set_time(0)
        ts_last_data_query_req.set_fetch_size(1000)
        physical_plan = processor.last_data_query_req_to_physical_plan(ts_last_data_query_req, zoneinfo("Asia/Shanghai"))
        assert plan14.get_operator_type() == OperatorType.LAST
        for i in range(len(paths)):
            path = paths[i]
            assert f"root.{i}.device{i}.sensor{i}" == physical_plan.get_paths()[i].get_full_path()
```

Note that this is a direct translation of the Java code into Python, and may not be idiomatic or efficient.