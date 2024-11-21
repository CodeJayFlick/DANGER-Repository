class TruncateCommittedEntryException(Exception):
    def __init__(self, index: int, committed: int) -> None:
        super().__init__(
            f"The committed entries cannot be truncated: parameter: {index}, commitIndex : {committed}"
        )
