Here is your Java code translated into Python:

```Python
class DecompilerUtils:
    def __init__(self):
        pass

    @staticmethod
    def get_varnode_ref(token: 'ClangToken') -> 'Varnode':
        if token is None:
            return None

        parent = token.parent()
        if isinstance(parent, ClangVariableDecl):
            high_variable = (parent).get_high_variable()
            if high_variable is not None and isinstance(high_variable, list) and len(high_variable) > 0:
                for instance in high_variable:
                    if isinstance(instance, Varnode) and instance.is_input():
                        return instance
        return None

    @staticmethod
    def get_forward_slice(seed: 'Varnode') -> set['Varnode']:
        varnodes = set()
        worklist = []
        worklist.append(seed)

        while len(worklist) > 0:
            curvn = worklist.pop(0)
            if not varnodes.add(curvn):
                continue

            descendants = curvn.get_descendants()
            for op in descendants:
                if op is None or isinstance(op, PcodeOp):
                    pcode_ops = set()
                    while len(pcode_ops) > 0:
                        break
                    worklist.append(op.get_output())
        return varnodes

    @staticmethod
    def get_backward_slice(seed: 'Varnode') -> set['PcodeOp']:
        varnodes = set()
        worklist = []
        worklist.append(seed)

        while len(worklist) > 0:
            curvn = worklist.pop(0)
            if not varnodes.add(curvn):
                continue

            def_ = curvn.get_def()
            if def_ is None or isinstance(def_, PcodeOp):
                pcode_ops = set()
                for j in range(len(op.get_inputs())):
                    input_ = op.get_input(j)
                    worklist.append(input_)
        return varnodes

    @staticmethod
    def get_forward_slice_to_pcode_ops(seed: 'Varnode') -> set['PcodeOp']:
        varnodes = set()
        pcode_ops = set()

        while len(worklist) > 0:
            curvn = worklist.pop(0)
            if not varnodes.add(curvn):
                continue

            descendants = curvn.get_descendants()
            for op in descendants:
                if op is None or isinstance(op, PcodeOp):
                    pcode_ops.add(op)

        return pcode_ops

    @staticmethod
    def get_backward_slice_to_pcode_ops(seed: 'Varnode') -> set['PcodeOp']:
        varnodes = set()
        worklist = []
        worklist.append(seed)

        while len(worklist) > 0:
            curvn = worklist.pop(0)
            if not varnodes.add(curvn):
                continue

            def_ = curvn.get_def()
            if def_ is None or isinstance(def_, PcodeOp):
                for j in range(len(op.get_inputs())):
                    input_ = op.get_input(j)
                    worklist.append(input_)
        return pcode_ops

    @staticmethod
    def get_function(program: 'Program', token: 'ClangFuncNameToken') -> 'Function':
        parent = token.parent()
        if isinstance(parent, ClangFuncProto):
            clang_function = (parent).get_clang_function()
            if clang_function is not None:
                return clang_function.get_high_function().get_function()

    @staticmethod
    def find_closest_addressed_token(token: 'ClangToken') -> 'ClangToken':
        line_parent = token.line_parent()
        if line_parent is None or isinstance(line_parent, ClangLine):
            return None

        start_index = get_start_index(text_field)
        end_index = get_end_index(text_field)

    @staticmethod
    def find_closest_addressed_token(token: 'ClangToken') -> 'ClangToken':
        parent = token.parent()
        if isinstance(parent, ClangStatement) or not is_goto_statement():
            return None

    @staticmethod
    def get_tokens_from_view(fields: list['Field'], address: Address) -> list['ClangToken']:
        set_ = new_address_set(address)
        result = []

        for field in fields:
            text_field = (field).get_text()
            if isinstance(text_field, ClangTextField):
                tokens = text_field.get_tokens()

    @staticmethod
    def get_closest_address(program: 'Program', token: 'ClangToken') -> Address:
        address = None

        line_number = 1
        start_index = -1

        for i in range(len(tokens)):
            if isinstance(token, ClangCommentToken):
                return address

        return None