class EnumerateTypeApplier:
    def __init__(self, applicator, ms_type):
        self.applicator = applicator
        self.ms_type = ms_type

    def get_size(self):
        return 0

    def apply(self):
        data_type = self.apply_enumerate_ms_type(self.ms_type)
        # TODO: uncomment when above method not returning null
        # gh_data_type_db = self.applicator.resolve(data_type)

    @property
    def name(self):
        return self.field_name

    @property
    def numeric(self):
        return self.numeric


    def apply_enumerate_ms_type(self, type_):
        self.field_name = PdbNamespaceUtils.fix_unnamed(type_.name, 0)
        self.numeric = type_.numeric
        return None


# Usage:
applicator = "your_applicator_here"
ms_type = "your_ms_type_here"

applier = EnumerateTypeApplier(applicator, ms_type)

print(applier.name)  # prints the name of the applier
print(applier.numeric)  # prints the numeric value of the applier

# calling apply method:
applier.apply()
