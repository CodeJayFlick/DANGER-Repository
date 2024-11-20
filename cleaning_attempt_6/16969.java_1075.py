import typing as t

class ICrossSpaceMergeFileSelector:
    """IMergeFileSelector selects a set of files from given seqFiles and unseqFiles which can be merged
       without exceeding given memory budget.
    """

    def select(self) -> t.List[t.Any]:
        raise NotImplementedError("Must implement the `select` method")

    def get_concurrent_merge_num(self) -> int:
        raise NotImplementedError("Must implement the `get_concurrent_merge_num` method")
