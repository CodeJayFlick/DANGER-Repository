Here is the translation of the Java code to Python:

```Python
import os
from typing import Dict, List, Iterator

class MeasurementChunkMetadataListMapIteratorTest:
    def __init__(self):
        self.FILE_PATH = 'outputDataFile'
        self.conf = TSFileDescriptor.getInstance().getConfig()
        self.max_degree_of_index_node = self.conf.get_max_degree_of_index_node()

    @classmethod
    def before(cls):
        cls.conf.set_max_degree_of_index_node(3)

    @classmethod
    def after(cls):
        os.remove(self.FILE_PATH)
        cls.conf.set_max_degree_of_index_node(cls.max_degree_of_index_node)

    def test_correctness(self, device_num: int, measurement_num: int) -> None:
        self.generate_file(device_num, measurement_num)
        
        try:
            file_reader = TsFileSequenceReader(self.FILE_PATH)
            device_measurement_list_map = file_reader.get_device_measurements_map()
            
            devices = file_reader.get_all_devices()

            expected_device_measurement_chunk_metadata_list_map = {}
            for device in devices:
                for measurement in device_measurement_list_map[device]:
                    if not expected_device_measurement_chunk_metadata_list_map.get(device):
                        expected_device_measurement_chunk_metadata_list_map[device] = {}
                    expected_device_measurement_chunk_metadata_list_map[device][measurement] = file_reader.get_chunk_metadata_list(Path(device, measurement))

            for device in devices:
                actual = {}
                iterator = file_reader.get_measurement_chunk_metadata_list_map_iterator(device)
                while iterator.has_next():
                    next_ = iterator.next()
                    for entry in next_.items():
                        if not actual.get(entry[0]):
                            actual[entry[0]] = []
                        actual[entry[0]].extend(entry[1])
                
                self.check_correctness(expected_device_measurement_chunk_metadata_list_map, actual)

            # test not exist device
            iterator = file_reader.get_measurement_chunk_metadata_list_map_iterator("dd")
            assert not iterator.has_next()

        finally:
            os.remove(self.FILE_PATH)
    
    def check_correctness(self, expected: Dict[str, Dict[str, List[IChunkMetadata]]], actual: Dict[str, Dict[str, List[ChunkMetadata]]]) -> None:
        for device in expected.keys():
            self.assertEqual(expected.get(device).keys(), actual.get(device).keys())
            for measurement in expected[device].keys():
                list_expected = expected[device][measurement]
                list_actual = actual[device][measurement]
                self.assertEqual(len(list_expected), len(list_actual))
                for i, (expected_chunk_metadata_list, actual_chunk_metadata_list) in enumerate(zip(list_expected, list_actual)):
                    self.assertEqual(str(expected_chunk_metadata_list[i]), str(actual_chunk_metadata_list[i]))

    def test_sequentiality(self, device_num: int, measurement_num: int) -> None:
        self.generate_file(device_num, measurement_num)

        try:
            file_reader = TsFileSequenceReader(self.FILE_PATH)
            for device in file_reader.get_all_devices():
                iterator = file_reader.get_measurement_chunk_metadata_list_map_iterator(device)
                
                last_measurement = None
                while iterator.has_next():
                    next_ = iterator.next()
                    for measurement, chunk_metadata_list in next_.items():
                        if last_measurement:
                            self.assertTrue(last_measurement < measurement)
                        last_measurement = measurement

        finally:
            os.remove(self.FILE_PATH)

    def generate_file(self, device_num: int, measurement_num: int) -> None:
        # implement the logic to generate a file
        pass


class TsFileSequenceReader:
    def __init__(self, path):
        self.path = path

    def get_device_measurements_map(self) -> Dict[str, List[str]]:
        return {}

    def get_all_devices(self) -> List[str]:
        return []

    def get_chunk_metadata_list(self, path: Path) -> List[ChunkMetadata]:
        return []

    def get_measurement_chunk_metadata_list_map_iterator(self, device: str) -> Iterator[Dict[str, List[ChunkMetadata]]]:
        # implement the logic to iterate over measurement chunk metadata
        pass


class ChunkMetadata:
    def __init__(self):
        pass

    def __str__(self) -> str:
        return ""


class Path:
    def __init__(self, device: str, measurement: str):
        self.device = device
        self.measurement = measurement

    def __eq__(self, other):
        if isinstance(other, Path):
            return self.device == other.device and self.measurement == other.measurement
        else:
            return False


class IChunkMetadata:
    pass