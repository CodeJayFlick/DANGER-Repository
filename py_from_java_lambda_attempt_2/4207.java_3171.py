Here is the translation of the Java code to Python:

```Python
class GenericRefernenceBaseRelocationFixupHandler:
    def process_relocation(self, program: 'Program', relocation: 'Relocation', old_image_base: 'Address', new_image_base: 'Address') -> bool:
        size = program.compiler_spec.data_organization.pointer_size
        if size == 4:
            return self.handle_generically_32(program, relocation, old_image_base, new_image_base)
        elif size == 8:
            return self.handle_generically_64(program, relocation, old_image_base, new_image_base)
        else:
            return False

    def handles_program(self, program: 'Program') -> bool:
        # always return false so that this is not the chosen handler for a program by the plugin
        return False

    def has_matching_reference(self, program: 'Program', address: 'Address', candidate_relocation_value: 'Address') -> bool:
        cu = program.listing.get_code_unit_containing(address)
        references_from = cu.references_from
        for reference in references_from:
            if reference.to_address == candidate_relocation_value:
                return True
        return False

    def handle_generically_64(self, program: 'Program', relocation: 'Relocation', old_image_base: 'Address', new_image_base: 'Address') -> bool:
        diff = (new_image_base - old_image_base).get_long()
        address = relocation.get_address()
        memory = program.memory
        value = memory.get_long(address)
        new_value = value + diff

        candidate_relocation_value = new_image_base.get_new_address(new_value)
        if self.has_matching_reference(program, address, candidate_relocation_value):
            return self.process_64_bit_relocation(program, relocation, old_image_base, new_image_base)

        return False

    def handle_generically_32(self, program: 'Program', relocation: 'Relocation', old_image_base: 'Address', new_image_base: 'Address') -> bool:
        diff = (new_image_base - old_image_base).get_long()

        address = relocation.get_address()
        memory = program.memory
        value = memory.get_int(address) & 0xffffffff
        new_value = int(value + diff)
        candidate_relocation_value = new_image_base.get_new_address(new_value)

        if self.has_matching_reference(program, address, candidate_relocation_value):
            return self.process_32_bit_relocation(program, relocation, old_image_base, new_image_base)

        return False

    def process_64_bit_relocation(self, program: 'Program', relocation: 'Relocation', old_image_base: 'Address', new_image_base: 'Address') -> bool:
        # implementation
        pass

    def process_32_bit_relocation(self, program: 'Program', relocation: 'Relocation', old_image_base: 'Address', new_image_base: 'Address') -> bool:
        # implementation
        pass


class Program:
    compiler_spec = None  # assuming this is a property of the class
    listing = None  # assuming this is a property of the class
    memory = None  # assuming this is a property of the class

class Address:
    def get_long(self) -> int:  # implementation
        pass

    def get_int(self) -> int:  # implementation
        pass

    def subtract(self, other: 'Address') -> 'Address':
        return self  # implementing subtraction operation for addresses


class Memory:
    def get_long(self, address: 'Address') -> int:  # implementation
        pass

    def get_int(self, address: 'Address') -> int:  # implementation
        pass

    def get_new_address(self, value: int) -> 'Address':
        return self  # implementing new address operation for memory


class Relocation:
    def get_address(self) -> 'Address':  # implementation
        pass

# usage example:

fixup_handler = GenericRefernenceBaseRelocationFixupHandler()
program = Program()  # assuming this is a program object
relocation = Relocation()  # assuming this is a relocation object
old_image_base = Address()  # assuming this is an address object
new_image_base = Address()  # assuming this is an address object

result = fixup_handler.process_relocation(program, relocation, old_image_base, new_image_base)
print(result)