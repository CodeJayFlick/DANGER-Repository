class BootstrapMethods:
    def __init__(self):
        self.bootstrap_methods_reference = None
        self.number_of_bootstrap_arguments = None
        self.bootstrap_arguments = []

    def read_from_binary(self, reader):
        try:
            self.bootstrap_methods_reference = reader.read_short()
            self.number_of_bootstrap_arguments = reader.read_short()
            self.bootstrap_arguments = [reader.read_short() for _ in range(get_number_of_bootstrap_arguments())]
        except Exception as e:
            print(f"Error reading from binary: {e}")

    def get_bootstrap_methods_reference(self):
        return self.bootstrap_methods_reference & 0xffff

    def get_number_of_bootstrap_arguments(self):
        return self.number_of_bootstrap_arguments & 0xffff

    def get_bootstrap_arguments_entry(self, i):
        if i < len(self.bootstrap_arguments):
            return self.bootstrap_arguments[i] & 0xffff
        else:
            raise IndexError("Index out of range")

def to_data_type(self):
    structure = {"bootstrap_methods": {"type": "structure", "members": {}}}
    structure["bootstrap_methods"]["members"] = {
        "bootstrap_method_ref": {"type": "word"},
        "num_bootstrap_arguments": {"type": "word"}
    }
    if self.number_of_bootstrap_arguments > 0:
        array_type = {"type": "array", "size": self.number_of_bootstrap_arguments, "member_type": "word"}
        structure["bootstrap_methods"]["members"] = {
            **structure["bootstrap_methods"]["members"],
            "bootstrapArguments": array_type
        }
    return structure

def get_number_of_bootstrap_arguments():
    # This function is not implemented in the original Java code.
    pass
