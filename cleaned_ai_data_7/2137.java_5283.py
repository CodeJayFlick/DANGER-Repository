class TargetPointerDataType:
    def __init__(self):
        pass

    class DefaultTargetPointerDataType(TargetPointerDataType):
        def __init__(self, referent_type: 'TargetPointerType') -> None:
            self.referent_type = referent_type

        def get_referent_type(self) -> 'TargetPointerType':
            return self.referent_type
