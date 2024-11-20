Here is the translation of the Java code to Python:
```
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
```
Note that I used the `@property` decorator to create read-only properties for the `device` and `chunk_metadata_list` attributes. This is equivalent to the getter methods in Java.

Also, I assumed that the `ChunkMetadata` class is not provided, so I left it as a placeholder list of dictionaries. If you have the actual implementation of `ChunkMetadata`, please let me know!