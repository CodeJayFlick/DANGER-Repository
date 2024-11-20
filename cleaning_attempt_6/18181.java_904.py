class ChunkGroupMetadata:
    def __init__(self, device: str, chunk_metadata_list: list):
        self.device = device
        self.chunk_metadata_list = chunk_metadata_list

    @property
    def device(self) -> str:
        return self._device

    @property
    def chunk_metadata_list(self) -> list:
        return self._chunk_metadata_list


# Example usage:
if __name__ == "__main__":
    metadata1 = ChunkGroupMetadata("DeviceA", [{"start": 0, "end": 100}, {"start": 101, "end": 200}])
    print(metadata1.device)  # Output: DeviceA
    print(metadata1.chunk_metadata_list)  # Output: [{'start': 0, 'end': 100}, {'start': 101, 'end': 200}]
