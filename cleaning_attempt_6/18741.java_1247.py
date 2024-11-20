class DeleteBranchBuilder:
    def __init__(self):
        pass

    def delete(self) -> None:
        raise NotImplementedError("Method not implemented")

# Define exceptions
class NessieConflictException(Exception):
    pass


class NessieNotFoundException(Exception):
    pass
