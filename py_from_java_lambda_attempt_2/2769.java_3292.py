Here is the translation of the Java code into Python:

```Python
class PcodeExecutor:
    def __init__(self, language: 'SleighLanguage', arithmetic: 'PcodeArithmetic[T]', state: 'PcodeExecutorStatePiece[T,T]'):
        self.language = language
        self.arithmetic = arithmetic
        self.state = state

        self.pc = language.get_program_counter()
        self.pointer_size = language.get_default_space().get_pointer_size()

    def get_language(self):
        return self.language

    def get_arithmetic(self):
        return self.arithmetic

    def get_state(self):
        return self.state

    def execute_line(self, line: str) -> None:
        program = SleighProgramCompiler.compile_program(language, "line", [f"{line};"], SleighUseropLibrary.NIL)
        self.execute(program, SleighUseropLibrary.nil())

    def begin(self, program: 'PcodeProgram') -> 'PcodeFrame':
        return self.begin(program.code, program.userop_names)

    def execute(self, program: 'PcodeProgram', library: 'SleighUseropLibrary[T]') -> 'PcodeFrame':
        return self.execute(program.code, program.userop_names, library)

    def begin(self, code: list['PcodeOp'], userop_names: dict[int, str]) -> 'PcodeFrame':
        return PcodeFrame(language, code, userop_names)

    def execute(self, code: list['PcodeOp'], userop_names: dict[int, str], library: 'SleighUseropLibrary[T]') -> 'PcodeFrame':
        frame = self.begin(code, userop_names)
        self.finish(frame, library)
        return frame

    def finish(self, frame: 'PcodeFrame', library: 'SleighUseropLibrary[T]') -> None:
        while not frame.is_finished():
            self.step(frame, library)

    def step_op(self, op: 'PcodeOp', frame: 'PcodeFrame', library: 'SleighUseropLibrary[T]') -> None:
        behavior = OpBehaviorFactory.get_op_behavior(op.opcode)
        if behavior is None:
            raise LowlevelError(f"Unsupported pcode op {op}")
        if isinstance(behavior, UnaryOpBehavior):
            self.execute_unary_op(op, behavior)
            return
        if isinstance(behavior, BinaryOpBehavior):
            self.execute_binary_op(op, behavior)
            return

    def step(self, frame: 'PcodeFrame', library: 'SleighUseropLibrary[T]') -> None:
        try:
            self.step_op(frame.next_op(), frame, library)
        except PcodeExecutionException as e:
            if not hasattr(e, "frame"):
                setattr(e, "frame", frame)
            raise
        except Exception as e:
            raise PcodeExecutionException("Exception during pcode execution", frame, e)

    def execute_unary_op(self, op: 'PcodeOp', behavior: UnaryOpBehavior) -> None:
        in1_var = op.input[0]
        out_var = op.output
        in1 = self.state.get_var(in1_var)
        out = self.arithmetic.unary_op(behavior, out_var.size, in1_var.size, in1)
        self.state.set_var(out_var, out)

    def execute_binary_op(self, op: 'PcodeOp', behavior: BinaryOpBehavior) -> None:
        in1_var = op.input[0]
        in2_var = op.input[1]
        out_var = op.output
        in1 = self.state.get_var(in1_var)
        in2 = self.state.get_var(in2_var)
        out = self.arithmetic.binary_op(behavior, out_var.size, in1_var.size, in1, in2_var.size, in2)
        self.state.set_var(out_var, out)

    def execute_load(self, op: 'PcodeOp') -> None:
        space_id = int(self.get_int_const(op.input[0]))
        address_space = self.language.get_address_factory().get_address_space(space_id)
        offset = self.state.get_var(op.input[1])
        out_var = op.output
        out = self.state.get_var(address_space, offset, out_var.size, True)
        self.state.set_var(out_var, out)

    def execute_store(self, op: 'PcodeOp') -> None:
        space_id = int(self.get_int_const(op.input[0]))
        address_space = self.language.get_address_factory().get_address_space(space_id)
        offset = self.state.get_var(op.input[1])
        val_var = op.input[2]
        val = self.state.get_var(val_var)
        self.state.set_var(address_space, offset, val_var.size, True, val)

    def branch_to_offset(self, offset: T, frame: 'PcodeFrame') -> None:
        self.state.set_var(self.pc.address_space, self.pc.offset, (self.pc.bit_length + 7) // 8, False, offset)
        frame.finish_as_branch()

    def execute_branch(self, op: 'PcodeOp', frame: 'PcodeFrame') -> None:
        target = op.input[0].address
        if target.is_constant_address():
            frame.branch(int(target.offset))
        else:
            self.branch_to_offset(self.arithmetic.from_const(target.offset, self.pointer_size), frame)
            self.branch_to_address(target)

    def execute_conditional_branch(self, op: 'PcodeOp', frame: 'PcodeFrame') -> None:
        cond_var = op.input[1]
        cond = self.state.get_var(cond_var)
        if self.arithmetic.is_true(cond):
            self.execute_branch(op, frame)

    def execute_indirect_branch(self, op: 'PcodeOp', frame: 'PcodeFrame') -> None:
        offset = self.state.get_var(op.input[0])
        self.branch_to_offset(offset, frame)

        concrete = self.arithmetic.to_concrete(offset).value
        target = op.seqnum.target.new_address(concrete)
        self.branch_to_address(target)

    def execute_call(self, op: 'PcodeOp', frame: 'PcodeFrame') -> None:
        target = op.input[0].address
        if target.is_constant_address():
            frame.branch(int(target.offset))
        else:
            self.branch_to_offset(self.arithmetic.from_const(target.offset, self.pointer_size), frame)
            self.branch_to_address(target)

    def execute_indirect_call(self, op: 'PcodeOp', frame: 'PcodeFrame') -> None:
        self.execute_indirect_branch(op, frame)

    def get_userop_name(self, op_no: int, frame: 'PcodeFrame') -> str:
        if op_no < self.language.get_number_of_user_defined_op_names():
            return self.language.get_user_defined_op_name(op_no)
        else:
            return frame.get_userop_name(op_no)

    def execute_callother(self, op: 'PcodeOp', frame: 'PcodeFrame', library: 'SleighUseropLibrary[T]') -> None:
        op_no = int(self.get_int_const(op.input[0]))
        op_name = self.get_userop_name(op_no, frame)
        if op_name is None:
            raise AssertionError(f"Pcode userop {op_no} is not defined")
        op_def = library.get_userops().get(op_name)
        if op_def is None:
            raise SleighLinkException(f"Sleigh userop '{op_name}' is not in the library {library}")
        op_def.execute(self.state, op.output, [i for i in range(1, len(op.inputs))])

    def execute_return(self, op: 'PcodeOp', frame: 'PcodeFrame') -> None:
        self.execute_indirect_branch(op, frame)
```

Please note that this is a direct translation of the Java code into Python. The resulting Python code may not be idiomatic or optimized for performance.