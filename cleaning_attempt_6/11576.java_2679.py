class UnimplementedCallOtherException(Exception):
    def __init__(self, op: 'PcodeOpRaw', op_name: str) -> None:
        super().__init__(f"Unimplemented CALLOTHER pcodeop ({op_name}), PC={op.get_address()}")
        self.op = op
        self.op_name = op_name

    @property
    def call_other_op(self) -> 'PcodeOpRaw':
        return self.op

    @property
    def call_other_op_name(self) -> str:
        return self.op_name
