import io

class IChunkLoader:
    def load_chunk(self, chunk_metadata: dict) -> bytes:
        """Read all content of any chunk."""
        # TO DO: implement this method in your specific use case
        pass

    def close(self):
        """Close the file reader."""
        raise NotImplementedError("Method not implemented")
