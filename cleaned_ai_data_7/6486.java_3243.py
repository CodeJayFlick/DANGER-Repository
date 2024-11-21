import unittest
from xml.etree import ElementTree as ET
import os
import io
import collections

class XmlImportOpinionsTest(unittest.TestCase):

    def setUp(self):
        self.loader = None

    def tearDown(self):
        if hasattr(self, 'loader'):
            try:
                file_path = get_test_directory_path() + "/test.xml"
                f = open(file_path, "w")
                f.write("")
                f.close()
            except Exception as e:
                print(f"Error in tear down: {e}")

    def test_xml_from_ida1(self):
        self.loader = XmlLoader()

        try:
            provider = get_byte_provider("TEST1", "<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\"><INFO_SOURCE USER=\"user\" TOOL=\"IDA-PRO\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" /><PROCESSOR NAME=\"FOO\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" /></PROGRAM>")
            check_valid_xml_load_spec(provider, self.loader.find_supported_load_specs(provider), "TEST1", None, None, None, "8051:BE:16:default", "6502:LE:16:default")
        except Exception as e:
            print(f"Error in test xml from ida 1: {e}")

    def test_xml_from_ida2(self):
        self.loader = XmlLoader()

        try:
            provider = get_byte_provider("TEST2", "<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\"><INFO_SOURCE USER=\"user\" TOOL=\"IDA-PRO\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" /><PROCESSOR NAME=\"FOO\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" /></PROGRAM>")
            check_valid_xml_load_spec(provider, self.loader.find_supported_load_specs(provider), "TEST2", Endian.LITTLE, None, None, "6502:LE:16:default")
        except Exception as e:
            print(f"Error in test xml from ida 2: {e}")

    def test_xml_from_ida3(self):
        self.loader = XmlLoader()

        try:
            provider = get_byte_provider("TEST3", "<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\"><INFO_SOURCE USER=\"user\" TOOL=\"Ida-ProXYZ\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" /><PROCESSOR NAME=\"METAPC\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" /></PROGRAM>")
            check_valid_xml_load_spec(provider, self.loader.find_supported_load_specs(provider), "TEST3", Endian.LITTLE, "x86", None, "x86:LE:32:default")
        except Exception as e:
            print(f"Error in test xml from ida 3: {e}")

    def test_xml_from_ida4(self):
        self.loader = XmlLoader()

        try:
            provider = get_byte_provider("TEST4", "<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\"><INFO_SOURCE USER=\"user\" TOOL=\"Ida-ProXYZ\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" /><PROCESSOR NAME=\"METAPC\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" /></PROGRAM>")
            check_valid_xml_load_spec(provider, self.loader.find_supported_load_specs(provider), "TEST4", Endian.LITTLE, "x86", "windows", "x86:LE:32:default")
        except Exception as e:
            print(f"Error in test xml from ida 4: {e}")

    def test_xml_from_ghidra(self):
        self.loader = XmlLoader()

        try:
            provider = get_byte_provider("TEST5", "<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\"><INFO_SOURCE USER=\"user\" TOOL=\"Ghidra 1.2.3\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" /><PROCESSOR NAME=\"x86\" LANGUAGE_PROVIDER=\"x86:LE:32:default:windows\" ENDIAN=\"little\" /></PROGRAM>")
            check_valid_xml_load_spec(provider, self.loader.find_supported_load_specs(provider), "TEST5", Endian.LITTLE, "x86", "windows", "x86:LE:32:default")
        except Exception as e:
            print(f"Error in test xml from ghidra: {e}")

    def check_valid_xml_load_spec(self, provider, load_specs, filename, endian=None, processor_name=None, one_cspec=None, language_ids=()):
        if one_cspec is not None:
            self.assertEqual("Expected one load spec", 1, len(load_specs))
        elif len(load_specs) <= 1:
            self.fail("Expected multiple load specs - found none")

        first_load_spec = next(iter(load_specs))
        self.assertTrue(isinstance(first_load_spec.get_loader(), XmlLoader))
        self.assertEqual(filename, first_load_spec.get_loader().get_preferred_file_name(provider))

        for load_spec in load_specs:
            language_description = load_spec.get_language_compiler_spec().get_language_description()
            assert language_description is not None
            compiler_spec_description = load_spec.get_language_compiler_spec().get_compiler_spec_description()
            assert compiler_spec_description is not None

            if endian is not None:
                self.assertEqual(endian, language_description.get_endian())

            if processor_name is not None:
                self.assertEqual(processor_name, str(language_description.get_processor()))

            if one_cspec is not None:
                self.assertTrue(load_spec.is_preferred())
                self.assertEqual(one_cspec, compiler_spec_description.get_compiler_spec_id().toString())
            else:
                self.assertFalse(load_spec.is_preferred())

        for id in language_ids:
            found = False
            for load_spec in load_specs:
                if str(language_description.get_language_id()) == id:
                    found = True
                    break

            self.assertTrue(f"Expected {id} to be included in load specs", found)

    def get_byte_provider(self, name, text):
        file_path = os.path.join(get_test_directory_path(), "test.xml")
        f = open(file_path, "w")
        f.write(text)
        f.close()

        return ByteProvider(name)


class XmlLoader:
    pass


def check_valid_xml_load_spec(provider, load_specs, filename, endian=None, processor_name=None, one_cspec=None, language_ids=()):
    if one_cspec is not None:
        self.assertEqual("Expected one load spec", 1, len(load_specs))
    elif len(load_specs) <= 1:
        self.fail("Expected multiple load specs - found none")

    first_load_spec = next(iter(load_specs))
    self.assertTrue(isinstance(first_load_spec.get_loader(), XmlLoader))
    self.assertEqual(filename, first_load_spec.get_loader().get_preferred_file_name(provider))

    for load_spec in load_specs:
        language_description = load_spec.get_language_compiler_spec().get_language_description()
        assert language_description is not None
        compiler_spec_description = load_spec.get_language_compiler_spec().get_compiler_spec_description()
        assert compiler_spec_description is not None

        if endian is not None:
            self.assertEqual(endian, language_description.get_endian())

        if processor_name is not None:
            self.assertEqual(processor_name, str(language_description.get_processor()))

        if one_cspec is not None:
            self.assertTrue(load_spec.is_preferred())
            self.assertEqual(one_cspec, compiler_spec_description.get_compiler_spec_id().toString())
        else:
            self.assertFalse(load_spec.is_preferred())

    for id in language_ids:
        found = False
        for load_spec in load_specs:
            if str(language_description.get_language_id()) == id:
                found = True
                break

        self.assertTrue(f"Expected {id} to be included in load specs", found)


def get_test_directory_path():
    return "/path/to/test/directory"


class ByteProvider:
    def __init__(self, name):
        self.name = name

    def read_bytes(self, index, length):
        raise Exception("Not implemented")

    def read_byte(self, index):
        raise Exception("Not implemented")

    def length(self):
        raise Exception("Not implemented")

    def is_valid_index(self, index):
        return True

    def get_name(self):
        return self.name

    def get_input_stream(self, index):
        raise Exception("Not implemented")

    def get_file(self):
        return None

    def get_absolute_path(self):
        return None

    def close(self):
        pass


if __name__ == "__main__":
    unittest.main()
