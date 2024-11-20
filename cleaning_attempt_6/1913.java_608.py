class AbstractModelForLldbScenarioStackTest:
    def __init__(self):
        self.expected_symbols = ["break_here", "funcC", "funcB", "funcA"]
        self.symbols_by_address = {}

    def get_specimen(self):
        return "STACK"

    def get_breakpoint_expression(self):
        return "break_here"

    def post_launch(self, process):
        session = process.get_parent().get_parent()
        modules = session.find("TargetModuleContainer", session.path)
        bin_mod = wait_on(modules.added_waiter.wait(PathUtils.index(modules.path, self.get_specimen())))
        
        symbols = session.find("TargetSymbolNamespace", bin_mod.path)
        for entry in wait_on(symbols.fetch_elements()).entry_set():
            self.symbols_by_address[entry.value.as(TargetSymbol).value] = entry.key

    def validate_frame_pc(self, index, pc):
        assert expected_symbols[index] == self.symbols_by_address.get(pc)

def wait_on(waiter):
    # implement this function to simulate waiting
    pass

import unittest
class Test(AbstractModelForLldbScenarioStackTest, unittest.TestCase):

if __name__ == "__main__":
    unittest.main()
