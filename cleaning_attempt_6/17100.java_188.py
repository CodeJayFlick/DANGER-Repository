class PartitionViolationException(Exception):
    def __init__(self, file):
        super().__init__(f"The data of file {file} cross partitions")
