class RenameVariableTask:
    def __init__(self, tool, program, panel, token, sym, st):
        self.high_symbol = sym
        self.exact_spot = token.get_varnode()
        self.h_function = sym.get_high_function()
        self.function = h_function.get_function()
        self.source_type = st

    def commit(self):
        if self.commit_required:
            HighFunctionDBUtil.commit_params_to_database(h_function, False, source_type)
            if source_type != SourceType.DEFAULT:
                HighFunctionDBUtil.commit_return_to_database(h_function, source_type)

        HighFunctionDBUtil.update_db_variable(high_symbol, new_name, None, source_type)


    def is_valid(self, new_nm):
        self.new_name = new_nm
        local_symbol_map = h_function.get_local_symbol_map()
        if local_symbol_map.contains_variable_with_name(new_name) or is_symbol_in_function(function, new_name):
            return False

        self.commit_required = AbstractDecompilerAction.check_full_commit(high_symbol, h_function)
        if commit_required:
            exact_spot = None  # Don't try to split out if we need to commit
        else:
            if exact_spot and not high_symbol.is_name_locked():
                try:
                    var = h_function.split_out_merge_group(exact_spot.get_high(), exact_spot)
                    self.high_symbol = var.symbol
                except PcodeException as e:
                    return False

        if high_symbol is None:
            return False

        return True


    def get_transaction_name(self):
        return "Rename Local Variable"


class HighFunctionDBUtil:
    @staticmethod
    def commit_params_to_database(h_function, full_commit, source_type):
        pass  # This method should be implemented in the Python code


    @staticmethod
    def commit_return_to_database(h_function, source_type):
        pass  # This method should be implemented in the Python code


    @staticmethod
    def update_db_variable(high_symbol, new_name, old_name, source_type):
        pass  # This method should be implemented in the Python code

class AbstractDecompilerAction:
    @staticmethod
    def check_full_commit(high_symbol, h_function):
        return False  # This method should be implemented in the Python code


# You can use this class to test your RenameVariableTask.
if __name__ == "__main__":
    tool = None
    program = None
    panel = None
    token = None
    sym = None
    st = None

    task = RenameVariableTask(tool, program, panel, token, sym, st)
    print(task.get_transaction_name())
