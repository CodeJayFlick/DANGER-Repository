import unittest
from typing import List, Map

class FileSnapshotTest(unittest.TestCase):

    def test_serialize(self):
        snapshot = FileSnapshot()
        data_files: List[RemoteTsFileResource] = []
        timeseries_schemas: List[TimeseriesSchema] = []
        ts_file_resources: List[TsFileResource] = TestUtils.prepare_ts_file_resources(0, 10, 10, 10, True)
        for i in range(10):
            data_file = RemoteTsFileResource(ts_file_resources[i], TestUtils.get_test_node(i))
            data_files.append(data_file)
            snapshot.add_file(ts_file_resources[i], TestUtils.get_test_node(i))
            timeseries_schemas.append(TestUtils.get_test_time_series_schema(0, i))

        self.assertEqual(data_files, snapshot.data_files)

        snapshot.set_timeseries_schemas(timeseries_schemas)

        self.assertEqual("FileSnapshot{10 files, 10 series, index-term: 0-0}", str(snapshot))

        buffer = snapshot.serialize()
        deserialized_snapshot = FileSnapshot()
        deserialized_snapshot.deserialize(buffer)
        self.assertEqual(snapshot, deserialized_snapshot)

    def test_install_single(self):
        add_net_failure = False
        self.test_install_single(add_net_failure)

    def test_install_single_with_failure(self):
        add_net_failure = True
        self.test_install_single(add_net_failure)

    def test_install_single(self, add_net_failure: bool):
        if add_net_failure:
            # Add net failure logic here

        snapshot = FileSnapshot()
        timeseries_schemas: List[TimeseriesSchema] = []
        ts_file_resources: List[TsFileResource] = TestUtils.prepare_ts_file_resources(0, 10, 10, 10, True)
        for i in range(10):
            snapshot.add_file(ts_file_resources[i], TestUtils.get_test_node(i))
            timeseries_schemas.append(TestUtils.get_test_time_series_schema(0, i))

        snapshot.set_timeseries_schemas(timeseries_schemas)

        default_installer = snapshot.default_installer(data_group_member)
        data_group_member.slot_manager().set_to_pulling(0, TestUtils.get_test_node(0))
        default_installer.install(snapshot, 0, False)

        self.assertEqual(SlotStatus.NULL, data_group_member.slot_manager().status(0))

        for timeseries_schema in timeseries_schemas:
            self.assertTrue(IoTDB.meta_manager.is_path_exist(PartialPath(timeseries_schema.full_path)))

        processor = StorageEngine.get_processor(new PartialPath(TestUtils.get_test_sg(0)))
        self.assertEqual(9, processor.partition_max_file_versions(0))
        loaded_files: List[TsFileResource] = processor.sequence_file_tree_set()
        self.assertEqual(len(ts_file_resources), len(loaded_files))

    def test_install_sync(self):
        use_async_server = ClusterDescriptor().get_config().is_use_async_server
        try:
            snapshot = FileSnapshot()
            timeseries_schemas: List[TimeseriesSchema] = []
            ts_file_resources: List[TsFileResource] = TestUtils.prepare_ts_file_resources(0, 10, 10, 10, True)
            for i in range(10):
                data_group_member.slot_manager().set_to_pulling(0, TestUtils.get_test_node(i))
                snapshot.add_file(ts_file_resources[i], TestUtils.get_test_node(i))
                timeseries_schemas.append(TestUtils.get_test_time_series_schema(0, i))

            snapshot.set_timeseries_schemas(timeseries_schemas)

            default_installer = snapshot.default_installer(data_group_member)
            data_group_member.slot_manager().set_to_pulling(0, TestUtils.get_test_node(0))
            default_installer.install(snapshot, 0, False)

            self.assertEqual(SlotStatus.NULL, data_group_member.slot_manager().status(0))

            for timeseries_schema in timeseries_schemas:
                self.assertTrue(IoTDB.meta_manager.is_path_exist(PartialPath(timeseries_schema.full_path)))

        finally:
            ClusterDescriptor().get_config().set_use_async_server(use_async_server)

    def test_install_with_mod_file(self):
        snapshot = FileSnapshot()
        timeseries_schemas: List[TimeseriesSchema] = []
        ts_file_resources: List[TsFileResource] = TestUtils.prepare_ts_file_resources(0, 10, 10, 10, True)
        for i in range(10):
            mod_file = ts_file_resources[i].get_mod_file()
            mod_file.write(new Deletion(PartialPath(TestUtils.get_test_sg(0)), 0, 10))
            mod_file.close()

            snapshot.add_file(ts_file_resources[i], TestUtils.get_test_node(i))
            timeseries_schemas.append(TestUtils.get_test_time_series_schema(0, i))

        buffer = snapshot.serialize()
        deserialized_snapshot = FileSnapshot()
        deserialized_snapshot.deserialize(buffer)

        default_installer = deserialized_snapshot.default_installer(data_group_member)
        data_group_member.slot_manager().set_to_pulling(0, TestUtils.get_test_node(0))
        default_installer.install(deserialized_snapshot, 0, False)

    def test_install_multiple(self):
        snapshot_map: Map[int, FileSnapshot] = {}
        for j in range(10):
            snapshot = FileSnapshot()
            timeseries_schemas: List[TimeseriesSchema] = []
            ts_file_resources: List[TsFileResource] = TestUtils.prepare_ts_file_resources(j, 10, 10, 10, True)
            for i in range(10):
                snapshot.add_file(ts_file_resources[i], TestUtils.get_test_node(i))
                timeseries_schemas.append(TestUtils.get_test_time_series_schema(0, i))

            snapshot.set_timeseries_schemas(timeseries_schemas)

        default_installer = snapshot_map[0].default_installer(data_group_member)
        default_installer.install(snapshot_map, False)

    def test_install_partial(self):
        # dataGroupMember already have some of the files
        snapshot = FileSnapshot()
        timeseries_schemas: List[TimeseriesSchema] = []
        ts_file_resources: List[TsFileResource] = TestUtils.prepare_ts_file_resources(0, 10, 10, 10, True)
        for i in range(10):
            snapshot.add_file(ts_file_resources[i], TestUtils.get_test_node(i))
            timeseries_schemas.append(TestUtils.get_test_time_series_schema(0, i))

        default_installer = snapshot.default_installer(data_group_member)
        data_group_member.slot_manager().set_to_pulling(0, TestUtils.get_test_node(0))
        default_installer.install(snapshot, 0, False)

if __name__ == '__main__':
    unittest.main()
