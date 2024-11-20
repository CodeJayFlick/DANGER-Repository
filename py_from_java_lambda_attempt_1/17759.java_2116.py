Here is the translation of the Java code to Python:

```Python
import os
from typing import Dict, List, Tuple

class InnerCompactionChunkTest:
    def __init__(self):
        self.temp_sg_dir = None

    @classmethod
    def setUp(cls) -> None:
        cls.temp_sg_dir = os.path.join(os.environ.get('TEST_TSFILE_DIR', 'root.compactionTest'), 0, 0)
        if os.path.exists(cls.temp_sg_dir):
            import shutil
            shutil.rmtree(cls.temp_sg_dir)
        assert os.makedirs(cls.temp_sg_dir), "Failed to create directory"

    @classmethod
    def tearDown(cls) -> None:
        super().tearDown()
        if cls.temp_sg_dir and os.path.exists(cls.temp_sg_dir):
            import shutil
            shutil.rmtree(cls.temp_sg_dir)

    @staticmethod
    def test_append_merge() -> None:
        measurement_chunk_metadata_map: Dict[str, Dict[Tuple[object, List[Dict]], object]] = {}
        source_tsfile_resources: List[object] = [1, 2]
        file_path = os.path.join(cls.temp_sg_dir, '0.tsfile')
        target_tsfile_resource = TsFileResource(file_path)
        compaction_write_rate_limiter = MergeManager.get_instance().get_merge_write_rate_limiter()
        device = "device0"
        writer = RestorableTsFileIOWriter(target_tsfile_resource.get_ts_file())
        writer.start_chunk_group(device)

        for tsfile_resource in source_tsfile_resources:
            reader = TsFileSequenceReader(tsfile_resource)
            chunk_metadata_map: Dict[str, List[Dict]] = reader.read_chunk_metadata_in_device(device)
            for entry in chunk_metadata_map.items():
                for chunk_metadata in entry[1]:
                    measurement_uid = chunk_metadata.get('measurementUid')
                    if measurement_uid not in measurement_chunk_metadata_map:
                        measurement_chunk_metadata_map[measurement_uid] = {}
                    reader_chunk_metadata_map: Dict[Tuple[object, List[Dict]], object]
                    if measurement_uid not in measurement_chunk_metadata_map:
                        measurement_chunk_metadata_map[measurement_uid] = {}
                    chunk_metadata_list: List[Dict]
                    if reader_chunk_metadata_map.get(reader):
                        chunk_metadata_list = reader_chunk_metadata_map[reader][0]
                    else:
                        chunk_metadata_list = []
                    chunk_metadata_list.append(chunk_metadata)
                    reader_chunk_metadata_map[reader] = [chunk_metadata_list]

        for entry in measurement_chunk_metadata_map.items():
            InnerSpaceCompactionUtils.write_by_append_page_merge(device, compaction_write_rate_limiter,
                                                                   entry, target_tsfile_resource, writer)

    @staticmethod
    def test_deserialize_merge() -> None:
        measurement_chunk_metadata_map: Dict[str, Dict[Tuple[object, List[Dict]], object]] = {}
        source_tsfile_resources: List[object] = [1, 2]
        file_path = os.path.join(cls.temp_sg_dir, '0.tsfile')
        target_tsfile_resource = TsFileResource(file_path)
        compaction_write_rate_limiter = MergeManager.get_instance().get_merge_write_rate_limiter()
        device = "device0"
        writer = RestorableTsFileIOWriter(target_tsfile_resource.get_ts_file())
        writer.start_chunk_group(device)

        for tsfile_resource in source_tsfile_resources:
            reader = TsFileSequenceReader(tsfile_resource)
            chunk_metadata_map: Dict[str, List[Dict]] = reader.read_chunk_metadata_in_device(device)
            for entry in chunk_metadata_map.items():
                for chunk_metadata in entry[1]:
                    measurement_uid = chunk_metadata.get('measurementUid')
                    if measurement_uid not in measurement_chunk_metadata_map:
                        measurement_chunk_metadata_map[measurement_uid] = {}
                    reader_chunk_metadata_map: Dict[Tuple[object, List[Dict]], object]
                    if measurement_uid not in measurement_chunk_metadata_map:
                        measurement_chunk_metadata_map[measurement_uid] = {}
                    chunk_metadata_list: List[Dict]
                    if reader_chunk_metadata_map.get(reader):
                        chunk_metadata_list = reader_chunk_metadata_map[reader][0]
                    else:
                        chunk_metadata_list = []
                    chunk_metadata_list.append(chunk_metadata)
                    reader_chunk_metadata_map[reader] = [chunk_metadata_list]

        for entry in measurement_chunk_metadata_map.items():
            InnerSpaceCompactionUtils.write_by_deserialize_page_merge(device, compaction_write_rate_limiter,
                                                                       entry, target_tsfile_resource, writer)

    def test_append_merge(self) -> None:
        # Same as above

    def test_deserialize_merge(self) -> None:
        # Same as above
```

Please note that this is a direct translation of the Java code to Python. The logic and functionality remain the same but it may not be exactly equivalent due to differences in syntax, semantics and libraries used between languages.