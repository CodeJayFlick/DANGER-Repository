import os
from typing import List, Map

class TsFileSequenceReader:
    def __init__(self, filename: str):
        self.filename = filename

    def read_head_magic(self) -> int:
        # TO DO: implement this method
        pass

    def read_tail_magic(self) -> int:
        # TO DO: implement this method
        pass

    def get_file_metadata_pos(self) -> int:
        # TO DO: implement this method
        return 0

    def get_file_metadata_size(self) -> int:
        # TO DO: implement this method
        return 0

    def position(self, pos: int):
        self.pos = pos

    def read_marker(self) -> int:
        # TO DO: implement this method
        pass

    def read_chunk_header(self, marker: int) -> dict:
        # TO DO: implement this method
        return {}

    def read_page_header(self, data_type: str, is_time_column_masked: bool) -> dict:
        # TO DO: implement this method
        return {}

    def read_page(self, page_header: dict, compression_type: int) -> bytes:
        # TO DO: implement this method
        pass

    def get_all_devices(self) -> List[str]:
        # TO DO: implement this method
        return []

    def read_chunk_metadata_in_device(self, device: str) -> Map[str, List[dict]]:
        # TO DO: implement this method
        return {}

def main():
    filename = "test.tsfile"
    if len(sys.argv) >= 1:
        filename = sys.argv[0]

    try:
        reader = TsFileSequenceReader(filename)
        print("file length:", os.path.getsize(filename))
        print("file magic head:", reader.read_head_magic())
        print("file magic tail:", reader.read_tail_magic())
        print("Level 1 metadata position:", reader.get_file_metadata_pos())
        print("Level 1 metadata size:", reader.get_file_metadata_size())

        while True:
            marker = reader.read_marker()
            if marker == MetaMarker.SEPARATOR:
                break

            switch (marker):
                case MetaMarker.CHUNK_HEADER | TsFileConstant.TIME_COLUMN_MASK:
                    # TO DO: implement this logic
                    pass
                case MetaMarker.ONLY_ONE_PAGE_CHUNK_HEADER | TsFileConstant.VALUE_COLUMN_MASK:
                    # TO DO: implement this logic
                    pass
                default:
                    print("Unexpected marker:", marker)

        devices = reader.get_all_devices()
        for device in devices:
            series_metadata = reader.read_chunk_metadata_in_device(device)
            print(f"[Device] {device}, Number of Measurements {len(series_metadata)}")
            for serie, chunk_metadatas in series_metadata.items():
                print(f"\t[Measurement]:{serie}")
                for chunk_metadata in chunk_metadatas:
                    print(f"\t\tFile offset:{chunk_metadata['offset_of_chunk_header']}")

    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    main()
