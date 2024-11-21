Here is the translation of the Java code into equivalent Python:

```Python
class MemberTypeApplier:
    def __init__(self, applicator: 'PdbApplicator', ms_type: 'AbstractMemberMsType'):
        self.applicator = applicator
        self.ms_type = ms_type

    def get_size(self) -> int:
        return 0

    def apply(self):
        try:
            data_type = self.apply_member_ms_type(self.ms_type)
            # TODO: uncomment when above method not returning null
            # gh_data_type_db = self.applicator.resolve(data_type)
        except PdbException as e:
            print(f"Pdb Exception occurred - {e}")
        except CancelledException as e:
            print(f"Cancelled Exception occurred - {e}")

    def get_name(self) -> str:
        return self.ms_type.name

    def get_offset(self) -> int:
        return self.ms_type.offset

    def get_attribute(self) -> 'ClassFieldMsAttributes':
        return self.ms_type.attribute

    def get_field_type_applier(self):
        field_type_record_number = self.ms_type.field_type_record_number
        return self.applicator.get_type_applier(field_type_record_number)

    def apply_member_ms_type(self, ms_type: 'AbstractMemberMsType') -> 'DataType':
        # TODO: implement this method
        pass

class PdbApplicator:
    def resolve(self, data_type) -> 'gh_data_type_db':
        pass

# Usage example:

applicator = PdbApplicator()
ms_type = AbstractMemberMsType()

applier = MemberTypeApplier(applicator, ms_type)
```

Please note that this is a direct translation of the Java code into Python. The actual implementation may vary based on your specific requirements and how you want to handle certain exceptions or methods in Python.