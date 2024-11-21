class MDBaseTestConfiguration:
    def __init__(self, quiet):
        self.quiet = quiet
        self.mdm = MDMang()

    def logger(self, message):
        if not self.quiet:
            print(message)

    def demangle_and_test(self, test_name, mangled_arg, mdtruth, mstruth, ghtruth, ms2013truth):
        self.mangled = mangled_arg
        self.set_truth(mdtruth, mstruth, ghtruth, ms2013truth)
        output_info = ""

        if self.verbose_output:
            output_info += "\n   Test: " + test_name.get_method_name()
            output_info += get_number_header(len(mangled_arg))
            output_info += get_test_header()

        # Meant to be overridden, as needed by extended classes
        do_demangle_symbol()

        do_basic_tests_and_output()

        # Meant to be overridden, as needed by extended classes
        do_extra_proc_check()

        self.logger(output_info)

    def is_mangled(self, s):
        if s[0] == '?':
            return True
        elif s.startswith('__'):
            return True
        elif (s[0] == '_' or Character.is_upper_case(s[1])):
            return True
        else:
            return False

    @staticmethod
    def get_number_header(length):
        header = ""
        remaining_chars = length
        while remaining_chars > len(print_header_tens):
            header += print_header_tens
            remaining_chars -= len(print_header_tens)
        if remaining_chars > 0:
            header += print_header_tens[:remaining_chars]
        remaining_chars = length
        while remaining_chars > len(print_header_ones):
            header += print_header_ones
            remaining_chars -= len(print_header_ones)
        if remaining_chars > 0:
            header += print_header_ones[:remaining_chars]
        return header

    @staticmethod
    def get_test_header():
        header = "Mangled: {}\nTruth: {}\nSzTruth: {}\n".format(self.mangled, self.truth, len(self.truth))
        return header

    def set_truth(self, mdtruth, mstruth, ghtruth, ms2013truth):
        if ms2013truth is not None:
            self.truth = ms2013truth
        else:
            self.truth = mstruth

    # Meant to be overridden, as needed by extended classes
    def do_demangle_symbol(self):
        try:
            demang_item = self.mdm.demangle(self.mangled, True)
            self-demangled = str(demang_item)
        except MDException:
            self-demanged = ""

    # Meant to be overridden, as needed by extended classes
    def do_basic_tests_and_output(self):
        if self.verbose_output:
            output_info += "Remains: {}\n".format(self.mdm.get_num_chars_remaining())
            if self-demangled is not None:
                output_info += "Demang: {}\nSzDem: {}\n".format(self-demangled, len(self-demangled))
            else:
                output_info += "Demang: null\nSzDem: N/A\n"

    # Meant to be overridden, as needed by extended classes
    def do_extra_proc_check(self):
        pass

print_header_tens = "0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"
print_header_ones = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"

class MDMang:
    def demangle(self, mangled_arg, is_mangled):
        pass

# Note: The above Python code does not include the actual implementation of the methods
