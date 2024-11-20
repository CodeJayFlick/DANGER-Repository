class IReaderByTimestamp:
    def get_values_in_timestamps(self, timestamps: list, length: int) -> list:
        """Returns the corresponding value under this timestamp.
        
        Returns None if no value under this timestamp.

        Note that calling this method will change the status of this reader irreversibly just like
        next. The difference is that get_values_in_timestamps advances towards the given timestamp.
        
        Attention: DO call this method with monotonically increasing timestamps. There is no guarantee 
        of correctness with any other way of calling. For example, DO NOT call this method twice 
        with the same timestamp."""
        pass

    def reader_is_empty(self) -> bool:
        """Returns whether there is no more data in reader.
        
        True means no more data. False means you can still get more data"""
        return False
