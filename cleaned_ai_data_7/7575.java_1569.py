import ghidra


class FunctionIDHeadlessPostscript:
    MINIMUM_FUNCTION_SIZE_IN_BYTES = 6

    def run(self):
        self.run_script("FixSwitchStatementsWithDecompiler.py")

        function_manager = current_program.get_function_manager()
        function_count = function_manager.get_function_count()

        if function_count == 0:
            print(f"{current_program.get_domain_file().get_pathname()} has no functions")
            return

        for function in function_manager.get_functions(True):
            body = function.get_body()
            if body.get_num_addresses() >= self.MINIMUM_FUNCTION_SIZE_IN_BYTES:
                return
        else:
            print(f"{current_program.get_domain_file().get_pathname()} has no normal-sized functions (>= {self.MINIMUM_FUNCTION_SIZE_IN_BYTES} bytes long)")


if __name__ == "__main__":
    script = FunctionIDHeadlessPostscript()
    script.run()

