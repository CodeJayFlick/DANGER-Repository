import os
from unittest import TestCase
from iotdb.tsfile.utils import SizeTieredCompactionLogger
from iotdb.tsfile.read.tsfilereader import TsFileSequenceReader
from iotdb.tsfile.write import WriteProcessException

class InnerSpaceCompactionUtilsTest(TestCase):

    def setUp(self):
        self.temp_sg_dir = os.path.join(os.environ.get('TEST_TSFILE_DIR', 'root.compactionTest'), str(0), str(0))
        if not os.path.exists(self.temp_sg_dir):
            os.makedirs(self.temp_sg_dir)
        super().setUp()

    def tearDown(self):
        super().tearDown()
        try:
            import shutil
            shutil.rmtree(os.path.join('target', 'testTsFile'))
        except Exception as e:
            print(f"Error in teardown: {e}")

    def test_compact(self):
        target_ts_file_resource = os.path.join(self.temp_sg_dir, str(0), IoTDBConstant.FILE_NAME_SEPARATOR + str(1) + IoTDBConstant.FILE_NAME_SEPARATOR + '0' + '.tsfile')
        if os.path.exists(target_ts_file_resource):
            try:
                import shutil
                shutil.rmtree(target_ts_file_resource)
            except Exception as e:
                print(f"Error in deleting file: {e}")

        size_tiered_compaction_logger = SizeTieredCompactionLogger(os.path.join(self.temp_sg_dir, '0' + '.compaction.log'))
        for resource in seq_resources:
            size_tiered_compaction_logger.log_file(SOURCE_NAME, resource)
        size_tiered_compaction_logger.log_sequence(True)

        InnerSpaceCompactionUtils.compact(target_ts_file_resource, seq_resources, COMPACTION_TEST_SG, size_tiered_compaction_logger, set(), True)
        size_tiered_compaction_logger.close()

        path = Path(device_ids[0], measurement_schemas[0].get_measurement_id())
        try:
            with TsFileSequenceReader(target_ts_file_resource) as reader:
                read_tsfile = ReadOnlyTsFile(reader)
                query_expression = QueryExpression.create([path], None)
                query_dataset = read_tsfile.query(query_expression)

                cut = 0
                record
                while query_dataset.has_next():
                    record = query_dataset.next()
                    self.assertEqual(record.get_timestamp(), record.get_fields()[0].get_double_v(), 0.001)
                    cut += 1

                self.assertEqual(500, cut)
        except Exception as e:
            print(f"Error in testing: {e}")
