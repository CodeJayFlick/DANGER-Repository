import io
from typing import List, Map

class IMetadataQuerier:
    def get_chunk_meta_data_list(self, path: str) -> List[dict]:
        # TO DO: implement this method in your Python code
        raise NotImplementedError("get_chunk_meta_data_list")

    def get_chunk_meta_data_map(self, paths: List[str]) -> Map[str, List[dict]]:
        # TO DO: implement this method in your Python code
        raise NotImplementedError("get_chunk_meta_data_map")

    def get_whole_file_metadata(self) -> dict:
        # TO DO: implement this method in your Python code
        raise NotImplementedError("get_whole_file_metadata")

    def load_chunk_metadatas(self, paths: List[str]) -> None:
        # TO DO: implement this method in your Python code
        pass

    def get_data_type(self, path: str) -> int:
        try:
            return 0  # Replace with actual implementation
        except NoMeasurementException as e:
            raise e
        except IOException as e:
            raise e

    def convert_space2_time_partition(
        self,
        paths: List[str],
        space_partition_start_pos: int,
        space_partition_end_pos: int,
    ) -> List[dict]:
        # TO DO: implement this method in your Python code
        pass

    def clear(self) -> None:
        # TO DO: implement this method in your Python code
        pass
