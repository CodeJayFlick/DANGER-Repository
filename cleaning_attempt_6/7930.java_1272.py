class MDGenericizeTestConfiguration:
    def __init__(self, quiet):
        super().__init__(quiet)
        self.mdm = MDMangGenericize()

    def do_extra_proc_check(self):
        if not hasattr(self, 'demang_item'):
            output_info.append("GDemang: N/A")
            return
        mangled_generic = (self.mdm).get_generic_symbol()
        output_info.append(get_number_header(len(mangled_generic)) + "\nGeneric: " + mangled_generic + "\n")
        mdm_generic = MDMang()
        demang_item_generic = mdm_generic.demangle(mangled_generic, False)
        if not hasattr(demang_item_generic, 'toString'):
            demangled_generic = ""
        else:
            demangled_generic = str(demang_item_generic)
        output_info.append("GDemang: " + demangled_generic + "\n")

class MDMangGenericize:
    def get_generic_symbol(self):
        # implement this method
        pass

class MDMang:
    def demangle(self, mangled, quiet=False):
        # implement this method
        return None

output_info = []
