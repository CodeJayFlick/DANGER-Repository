import unittest
from io import BytesIO
from urllib.parse import urlparse

class PreProcessorTest(unittest.TestCase):

    def setUp(self):
        self.parser = PreProcessor()
        self.baos = BytesIO()

    def testHeaderParsing(self):
        self.parser.setOutputStream(self.baos)
        resource_name = "PreProcessorTest.h"
        url = urlparse(PreProcessorTest.__file__).path + "/" + resource_name
        self.parser.parse(url)

        # Uncomment to print out parse results
        print(self.baos.getvalue().decode("ASCII"))

        end_str = self baos.getvalue().decode("ASCII").rpartition(";")[2]
        self.assertEqual(end_str, "theEnd();")

        self.assertTrue(baos.getvalue().decode("ASCII").find("extern int __declspec(\"fp(\\\"l\\\",  \" #bob \")\") __ifplbob;") != -1)

        dt_mgr = StandAloneDataTypeManager("parsed")
        self.parser.getDefinitions().populateDefineEquates(dt_mgr)

        path = "/PreProcessorTest.h"
        value = 32516
        def_name = "DefVal1"
        check_define(dt_mgr, path, value, def_name)

        value = 0x06010000 + 0xf1
        def_name = "DefVal2"
        check_define(dt_mgr, path, value, def_name)

        value = 0x60010001 & 0x21234 | 1
        def_name = "DefVal3"
        check_define(dt_mgr, path, value, def_name)

        value = 0x1 << (1 + 2 | 4)
        def_name = "DefVal4"
        check_define(dt_mgr, path, value, def_name)

        value = 0xFF000000L & ~(0x01000000L | 0x02000000L | 0x04000000L)
        def_name = "DefVal5"
        check_define(dt_mgr, path, value, def_name)

        value = ((0x000F0000L) | (0x00100000L) | 3)
        def_name = "DefVal6"
        check_define(dt_mgr, path, value, def_name)

        value = 0x40000000L
        def_name = "DefVal7"
        check_define(dt_mgr, path, value, def_name)

        value = (3 << 13) | (3 << 9) | 4
        def_name = "DefVal8"
        check_define(dt_mgr, path, value, def_name)

        value = ((0x7fff & ~(((1 << 4) - 1))))
        def_name = "DefVal9"
        check_define(dt_mgr, path, value, def_name)

        value = (0x7fff * 900L // 1000)
        def_name = "DefVal10"
        check_define(dt_mgr, path, value, def_name)

        value = 0
        def_name = "TOO_MANY_FISH"
        check_not_define(dt_mgr, path, def_name)

        value = 0x53977
        def_name = "ImOctal"
        check_define(dt_mgr, path, value, def_name)

        def_name = "TEST_FAILED"
        check_not_define(dt_mgr, path, def_name)

        def_name = "isDefineOnValue"
        value = 1
        check_define(dt_mgr, path, value, def_name)

        def_name = "BIGNUM"
        value = 64 * 16 + 16
        check_define(dt_mgr, path, value, def_name)

    def check_define(self, dt_mgr, path, value, def_name):
        data_type = dt_mgr.get_data_type(path, f"define_{def_name}")
        self.assertIsNotNone(data_type)
        self.assertIsInstance(data_type, Enum)
        self.assertEqual(value, getattr(data_type, def_name))

    def check_not_define(self, dt_mgr, path, def_name):
        data_type = dt_mgr.get_data_type(path, f"define_{def_name}")
        self.assertIsNone(data_type)

if __name__ == "__main__":
    unittest.main()
