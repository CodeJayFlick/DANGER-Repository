import unittest
from ghidra.app import analyzer
from ghidra.program.model.address import AbstractAddress
from ghidra.program.model.data import ByteDataType
from ghidra.util.exception import CancelledException


class CondenseFillerBytesAnalyzerTest(unittest.TestCase):

    def setUp(self):
        self.builder = ToyProgramBuilder("Test", True)
        self.program = self.builder.get_program()

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_determine_fill_value_single_pattern(self):

        filler_pattern = create_and_install_filler_pattern_single_pattern()
        analyzer = CondenseFillerBytesAnalyzer()
        listing = self.program.get_listing()
        auto_fill_value = analyzer.determine_fill_value(listing)
        self.assertEqual(filler_pattern, auto_fill_value)

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_determine_fill_value_two_patterns(self):

        filler_pattern = create_and_install_filler_pattern_two_patterns()
        analyzer = CondenseFillerBytesAnalyzer()
        listing = self.program.get_listing()
        auto_fill_value = analyzer.determine_fill_value(listing)
        self.assertEqual(filler_pattern, auto_fill_value)

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_collapse_filler_bytes_single_byte(self):

        filler_functions = install_filler_pattern_single_byte()
        run_analyzer()

        for ff in filler_functions:
            ff.assert_filled_correctly()

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_collapse_filler_bytes_multiple_bytes(self):

        filler_functions = install_filler_pattern_multiple_bytes()
        run_analyzer()

        for ff in filler_functions:
            ff.assert_filled_correctly()

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_collapse_filler_bytes_with_and_without_fillers(self):

        filler_functions = install_filler_pattern_with_and_without_fillers()
        run_analyzer()

        for ff in filler_functions:
            ff.assert_filled_correctly()

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_custom_fill_value_matching_patterns_get_changed(self):

        custom_pattern = "01"
        filler_functions = install_filler_pattern_01(custom_pattern)
        run_analyzer(custom_pattern)

        for ff in filler_functions:
            ff.assert_alignment_type_applied()

    @unittest.skipIf(not hasattr(analyzer, 'CondenseFillerBytesAnalyzer'), "This test is only applicable to GHIDRA")
    def test_custom_fill_value_non_matching_patterns_do_not_get_changed(self):

        custom_pattern = "AB"
        filler_functions = install_filler_pattern_01(custom_pattern)
        run_analyzer(custom_pattern)

        for ff in filler_functions:
            ff.assert_alignment_type_not_applied()

    # Private Methods

    def create_and_install_filler_pattern_single_pattern(self):
        function1 = self.builder.create_empty_function("function1", "0x10", 10, ByteDataType())
        body = function1.get_body()
        max_address = body.get_max_address()

        filler_address = max_address.next()
        addr = str(filler_address)
        pattern = "ba"
        self.builder.set_bytes(addr, pattern)

        return pattern

    def create_and_install_filler_pattern_two_patterns(self):
        function1 = self.builder.create_empty_function("function1", "0x10", 10, ByteDataType())
        body = function1.get_body()
        max_address = body.get_max_address()

        filler_address = max_address.next()
        addr = str(filler_address)
        pattern = "ba"
        self.builder.set_bytes(addr, pattern)

        for _ in range(2):
            function2 = self.builder.create_empty_function("function2", "0x20", 10, ByteDataType())
            body = function2.get_body()
            max_address = body.get_max_address()

            filler_address = max_address.next()
            addr = str(filler_address)
            self.builder.set_bytes(addr, pattern)

        return pattern

    def install_filler_pattern_single_byte(self):
        function1 = self.builder.create_empty_function("function1", "0x10", 10, ByteDataType())
        body = function1.get_body()
        max_address = body.get_max_address()

        filler_address = max_address.next()
        addr = str(filler_address)
        pattern = "90"
        self.builder.set_bytes(addr, pattern)

        return [FillerFunction(function1, 1)]

    def install_filler_pattern_multiple_bytes(self):
        function1 = self.builder.create_empty_function("function1", "0x10", 10, ByteDataType())
        body = function1.get_body()
        max_address = body.get_max_address()

        filler_address = max_address.next()
        addr = str(filler_address)
        pattern = "90"
        self.builder.set_bytes(addr, pattern)

        return [FillerFunction(function1, 3)]

    def install_filler_pattern_with_and_without_fillers(self):
        function1 = self.builder.create_empty_function("function1", "0x10", 10, ByteDataType())
        body = function1.get_body()
        max_address = body.get_max_address()

        filler_address = max_address.next()
        addr = str(filler_address)
        pattern = "90"
        self.builder.set_bytes(addr, pattern)

        for _ in range(2):
            function2 = self.builder.create_empty_function("function2", "0x20", 10, ByteDataType())
            body = function2.get_body()
            max_address = body.get_max_address()

            filler_address = max_address.next()
            addr = str(filler_address)
            self.builder.set_bytes(addr, pattern)

        return [FillerFunction(function1, 3), FillerFunction(function2, 2)]

    def run_analyzer(self):
        tx_id = self.program.start_transaction("Analyze")

        try:
            analyzer = CondenseFillerBytesAnalyzer()
            if filler_value is not None:
                analyzer.filler_value = filler_value
            analyzer.added(self.program, new AddressSet(), TaskMonitor.DUMMY, MessageLog())
        finally:
            self.program.end_transaction(tx_id, True)

    def set_bytes(self, address, pattern):
        addr = str(address)
        for _ in range(count):
            self.builder.set_bytes(addr, pattern)
            address = address.next()
            addr = str(address)


class FillerFunction:

    def __init__(self, function, count):
        self.function = function
        self.filler_byte_count = count

    def get_filler_start(self):
        body = self.function.get_body()
        return body.get_max_address().next()

    def assert_filled_correctly(self):
        if self.isValid:
            self.assert_alignment_type_applied()
        else:
            self.assert_alignment_type_not_applied()


if __name__ == '__main__':
    unittest.main()
