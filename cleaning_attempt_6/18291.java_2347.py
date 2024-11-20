import io
from typing import List

class AbstractFileSeriesReader:
    def __init__(self, chunk_loader: object, chunk_metadata_list: List[object], filter: object):
        self.chunk_loader = chunk_loader
        self.chunk_metadata_list = chunk_metadata_list
        self.filter = filter
        self.chunk_to_read = 0

    def hasNextBatch(self) -> bool:
        if self.chunk_reader and self.chunk_reader.has_next_satisfied_page():
            return True

        while self.chunk_to_read < len(self.chunk_metadata_list):
            chunk_meta_data = next_chunk_meta()
            if self.chunk_satisfied(chunk_meta_data):
                init_chunk_reader(chunk_meta_data)
                if self.chunk_reader.has_next_satisfied_page():
                    return True
            break
        return False

    def next_batch(self) -> object:
        return self.chunk_reader.next_page_data()

    def close(self) -> None:
        self.chunk_loader.close()

    def init_chunk_reader(self, chunk_meta_data: object) -> None:
        # Abstract method implementation goes here

    def chunk_satisfied(self, chunk_meta_data: object) -> bool:
        # Abstract method implementation goes here

    def next_chunk_meta(self) -> object:
        return self.chunk_metadata_list[self.chunk_to_read]
        self.chunk_to_read += 1
