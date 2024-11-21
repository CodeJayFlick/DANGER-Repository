Here is the translation of the Java code into equivalent Python:

```Python
class ProcedureTypeApplier:
    def __init__(self, applicator: 'PdbApplicator', ms_type: 'AbstractProcedureMsType') -> None:
        super().__init__(applicator, ms_type)

    @property
    def size(self) -> int:
        return 0

    @property
    def calling_convention(self) -> str:
        return (self.ms_type).get_calling_convention()

    @property
    def has_this_pointer(self) -> bool:
        return False

    @property
    def return_record_number(self) -> int:
        return (self.ms_type).get_return_record_number()

    @property
    def arg_list_record_number(self) -> int:
        return (self.ms_type).get_arg_list_record_number()

    def apply(self):
        self.apply_function(self.calling_convention, not self.has_this_pointer)

#     proc_type = self.ms_type
#     self.apply_function(proc_type.get_calling_convention(), False, proc_type.get_return_type_index(),
#                         proc_type.get_arg_list_type_index())
#     definition = self.apply_function(proc_type.get_calling_convention(), False,
#                                     proc_type.get_return_type_index(), proc_type.get_arg_list_type_index())
#     gh_data_type_db = self.applicator.resolve(definition)
```

Please note that Python does not support direct translation of Java code. It's a different language with its own syntax and semantics. This is an equivalent implementation in Python, but it may behave differently than the original Java code due to differences between languages.