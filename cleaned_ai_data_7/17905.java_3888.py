import logging
from typing import List

class MManagerImproveTest:
    logger = logging.getLogger(__name__)

    TIMESERIES_NUM = 1000
    DEVICE_NUM = 10
    m_manager = None

    def setUp(self):
        self.logger.info("Setting up environment")
        EnvironmentUtils.envSetUp()
        self.m_manager = IoTDB.metaManager
        self.m_manager.set_storage_group(PartialPath("root.t1.v2"))

        for j in range(DEVICE_NUM):
            for i in range(TIMESERIES_NUM):
                path = f"root.t1.v2.d{j}.s{i}"
                self.m_manager.create_timeseries(
                    PartialPath(path),
                    TSDataType.TEXT,
                    TSEncoding.PLAIN,
                    TSFileDescriptor.get_instance().get_config().get_compressor(),
                    {}
                )

    def check_set_up(self):
        m_manager = IoTDB.metaManager

        assert m_manager.is_path_exist(PartialPath("root.t1.v2.d3.s5"))
        assert not m_manager.is_path_exist(PartialPath(f"root.t1.v2.d9.s{TIMESERIES_NUM}"))
        assert not m_manager.is_path_exist(PartialPath("root.10"))

    def analyse_time_cost(self):
        string_combine = 0
        path_exist = 0
        list_init = 0
        check_filelevel = 0
        get_seriestype = 0

        device_id = "root.t1.v2.d3"
        measurement = "s5"
        path = f"{device_id}{TsFileConstant.PATH_SEPARATOR}{measurement}"

        start_time = int(time.time())
        for _ in range(100000):
            assert m_manager.is_path_exist(PartialPath(path))
        end_time = int(time.time())
        path_exist += (end_time - start_time)

        start_time = int(time.time())
        end_time = int(time.time())
        list_init += (end_time - start_time)

        start_time = int(time.time())
        for _ in range(100000):
            ts_data_type = m_manager.get_series_type(PartialPath(path))
            assert ts_data_type == TSDataType.TEXT
        end_time = int(time.time())
        get_seriestype += (end_time - start_time)

        self.logger.debug(f"string combine: {string_combine}")
        self.logger.debug(f"series path exist: {path_exist}")
        self.logger.debug(f"list init: {list_init}")
        self.logger.debug(f"check file level: {check_filelevel}")
        self.logger.debug(f"get series type: {get_seriestype}")

    def do_origin_test(self, device_id: str, measurement_list: List[str]) -> None:
        for measurement in measurement_list:
            path = f"{device_id}{TsFileConstant.PATH_SEPARATOR}{measurement}"
            assert m_manager.is_path_exist(PartialPath(path))
            ts_data_type = m_manager.get_series_type(PartialPath(path))
            assert ts_data_type == TSDataType.TEXT

    def do_path_loop_once_test(self, device_id: str, measurement_list: List[str]) -> None:
        for measurement in measurement_list:
            path = f"{device_id}{TsFileConstant.PATH_SEPARATOR}{measurement}"
            ts_data_type = m_manager.get_series_type(PartialPath(path))
            assert ts_data_type == TSDataType.TEXT

    def do_cache_test(self, device_id: str, measurement_list: List[str]) -> None:
        try:
            node = m_manager.get_device_node_with_auto_create(PartialPath(device_id))
            for s in measurement_list:
                assert node.has_child(s)
                measurement_node = node.child(s).as_measurement_mnode()
                ts_data_type = measurement_node.schema.type
                assert ts_data_type == TSDataType.TEXT
        except IOException as e:
            raise MetadataException(e)

    def improve_test(self) -> None:
        m_manager = IoTDB.metaManager

        device_id_list = [f"root.t1.v2.d{i}" for i in range(DEVICE_NUM)]
        measurement_list: List[str] = []
        for _ in range(TIMESERIES_NUM):
            measurement_list.append(f"s{i}")

        start_time = int(time.time())
        for device_id in device_id_list:
            self.do_origin_test(device_id, measurement_list)
        end_time = int(time.time())
        self.logger.debug(f"origin: {end_time - start_time}")

        start_time = int(time.time())
        for device_id in device_id_list:
            self.do_path_loop_once_test(device_id, measurement_list)
        end_time = int(time.time())
        self.logger.debug(f"series path loop once: {end_time - start_time}")

        start_time = int(time.time())
        for device_id in device_id_list:
            self.do_cache_test(device_id, measurement_list)
        end_time = int(time.time())
        self.logger.debug(f"add cache: {end_time - start_time}")

    def tearDown(self):
        EnvironmentUtils.clean_env()
