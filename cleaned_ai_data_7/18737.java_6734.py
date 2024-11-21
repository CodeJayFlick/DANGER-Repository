class AssignBranchBuilder:
    def __init__(self):
        pass

    def assign_to(self, reference: 'Reference') -> 'AssignBranchBuilder':
        return self

    async def assign(self) -> None:
        raise NessieNotFoundException("Nessie not found")
        #raise NessieConflictException("Nessie conflict")

class Reference:
    pass
