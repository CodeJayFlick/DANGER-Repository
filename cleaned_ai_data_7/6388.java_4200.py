import unittest
from ghidra_app import *
from program_util import *

class LocationReferencesPlugin1Test(unittest.TestCase):

    def test_field_name_location_descriptor_structure_field_name_array_in_structure(self):
        open_data(0x01005540)
        
        go_to(addr(0x01005541), FieldNameFieldFactory.FIELD_NAME, 1)

        location = code_browser.get_current_location()
        descriptor = reference_utils.get_location_descriptor(location)
        self.assertIsInstance(descriptor, StructureMemberLocationDescriptor)


if __name__ == '__main__':
    unittest.main()
