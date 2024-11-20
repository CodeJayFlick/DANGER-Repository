Here is a translation of the Java code into equivalent Python:

```Python
class CreateArrayCmd:
    def __init__(self, addr, num_elements, data_type, element_length):
        self.addr = addr
        self.num_elements = num_elements
        self.data_type = data_type
        self.element_length = element_length

    def apply_to(self, obj):
        program = Program(obj)
        listing = program.get_listing()
        try:
            adt = ArrayDataType(data_type, num_elements, element_length, program.get_data_type_manager())
            length = adt.get_length()

            end_addr = addr.add_no_wrap(length - 1)
            set = AddressSet(addr, end_addr)
            iter = listing.get_instructions(set, True)
            if iter.has_next():
                self.msg = "Can't create data because the current selection contains instructions"
                return False
            listing.clear_code_units(addr, end_addr, False)
            listing.create_data(addr, adt, length)

        except AddressOverflowException:
            self.msg = "Can't create data because length exceeds address space"
            return False

        except (IllegalArgumentException, CodeUnitInsertionException) as e:
            self.msg = str(e)
            return False

        except RuntimeError as e:
            self.msg = f"Unexpected error: {e}"
            Msg.error(self, self.msg, e)
            return False
        return True

    def get_status_msg(self):
        return self.msg

    def get_name(self):
        return "Create Array"


class Program:
    pass


class Listing:
    def __init__(self, program):
        self.program = program

    def get_listing(self):
        return self

    def clear_code_units(self, addr1, addr2, flag):
        pass

    def create_data(self, addr, adt, length):
        pass

    def get_instructions(self, set, flag):
        pass


class Address:
    def __init__(self):
        pass

    def add_no_wrap(self, offset):
        return self + offset

    def has_next(self):
        pass
```

Please note that Python does not have direct equivalent of Java's `Address`, `ArrayDataType` and other classes. These are custom classes in the original code which seem to be related to a specific domain (perhaps some kind of binary data processing).