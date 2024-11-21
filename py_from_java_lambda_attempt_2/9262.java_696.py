Here is the translation of the Java code into Python:

```Python
import os
from unittest import TestCase
from utilities.util.FileUtilities import delete_dir


class LocalBufferFileTest(TestCase):

    BUFFER_SIZE = 1024

    def setUp(self):
        self.test_dir = os.path.join(os.getcwd(), "LocalBufferFileTest")
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)
        else:
            for root, dirs, files in os.walk(self.test_dir):
                for f in files:
                    os.remove(os.path.join(root, f))
                for d in dirs:
                    delete_dir(os.path.join(root, d))

    def tearDown(self):
        if not self.test_dir is None and os.path.exists(self.test_dir):
            for root, dirs, files in os.walk(self.test_dir):
                for f in files:
                    os.remove(os.path.join(root, f))
                for d in dirs:
                    delete_dir(os.path.join(root, d))

    def test_temp_file(self):

        file = None
        bf = None

        try:

            bf = LocalBufferFile(BUFFER_SIZE, "test", ".tmp")
            file = bf.get_file()
            self.assertTrue(file.exists())

            self.assertEqual(BUFFER_SIZE, bf.get_buffer_size())
            self.assertEqual(0, len(bf.get_free_indexes()))
            self.assertEqual(0, bf.get_index_count())

            do_write_read_test(bf)

            bf.close()
            bf = None

            self.assertFalse(file.exists())
            file = None
        finally:
            if not bf is None:
                try:
                    bf.close()
                except Exception as e:
                    pass
            if not file is None and file.exists():
                os.remove(str(file))

    def test_file_save(self):

        file = open(os.path.join(self.test_dir, "test.bf"), 'wb')
        bf = LocalBufferFile(file.name, BUFFER_SIZE)

        try:

            self.assertTrue(file.exists())
            self.assertEqual(BUFFER_SIZE, bf.get_buffer_size())

            self.assertEqual(0, len(bf.get_free_indexes()))
            self.assertEqual(0, bf.get_index_count())

            free_list = do_write_read_test(bf)
            index_cnt = bf.get_index_count()
            file_id = bf.get_file_id()

            self.assertNotEqual(file_id, 0)

            bf.set_parameter("TestParm1", 321)
            bf.set_parameter("TestParm2", 543)

            bf.close()
            bf = None

            self.assertTrue(file.exists())

            # Reopen buffer file for reading
            bf = LocalBufferFile(file.name, True)
            self.assertEqual(index_cnt, bf.get_index_count())
            self.assertEqual(free_list, bf.get_free_indexes())
            self.assertEqual(file_id, bf.get_file_id())
            self.assertEqual(321, bf.get_parameter("TestParm1"))
            self.assertEqual(543, bf.get_parameter("TestParm2"))

            do_read_test2(bf)

            bf.close()
            bf = None

            self.assertTrue(file.exists())

        finally:
            if not bf is None:
                try:
                    bf.close()
                except Exception as e:
                    pass
            file.close()

    def test_file_modify(self):

        file = open(os.path.join(self.test_dir, "test.bf"), 'wb')
        bf = LocalBufferFile(file.name, BUFFER_SIZE)

        try:

            self.assertTrue(file.exists())
            self.assertEqual(BUFFER_SIZE, bf.get_buffer_size())

            self.assertEqual(0, len(bf.get_free_indexes()))
            self.assertEqual(0, bf.get_index_count())

            free_list = do_write_read_test(bf)
            index_cnt = bf.get_index_count()
            file_id = bf.get_file_id()

            self.assertNotEqual(file_id, 0)

            bf.set_parameter("TestParm1", 321)
            bf.set_parameter("TestParm2", 543)

            bf.close()
            bf = None

            self.assertTrue(file.exists())

            # Reopen buffer file for modification
            bf = LocalBufferFile(file.name, False)
            self.assertEqual(index_cnt, bf.get_index_count())
            self.assertEqual(free_list, bf.get_free_indexes())
            self.assertEqual(file_id, bf.get_file_id())
            self.assertEqual(321, bf.get_parameter("TestParm1"))
            self.assertEqual(543, bf.get_parameter("TestParm2"))

            do_read_test2(bf)

            bf.set_parameter("TestParm1", 322)
            bf.set_parameter("TestParm2", 544)

            data = bytearray(BUFFER_SIZE - 1)
            buf = DataBuffer(data)

            for i in range(len(data)):
                data[i] = 0xf2
            buf.id = 12

            bf.put(buf, 2)

            do_read_test1(bf)

            bf.set_free_indexes([0])

            bf.close()
            bf = None

            self.assertTrue(file.exists())

            # Reopen buffer file for reading
            bf = LocalBufferFile(file.name, True)
            self.assertEqual(index_cnt, bf.get_index_count())
            self.assertEqual(0, len(bf.get_free_indexes()))
            self.assertEqual(file_id, bf.get_file_id())
            self.assertEqual(322, bf.get_parameter("TestParm1"))
            self.assertEqual(544, bf.get_parameter("TestParm2"))

            do_read_test1(bf)

            bf.close()
            bf = None

            self.assertTrue(file.exists())

        finally:
            if not bf is None:
                try:
                    bf.close()
                except Exception as e:
                    pass
            file.close()

    def do_write_read_test(self, bf):

        buf = DataBuffer(bytearray(BUFFER_SIZE - 1))

        try:

            bf.get(buf, 0)
            self.fail("Expected EOFException getting non-exting buffer")

        except EOFError as e:

            # expected

        try:

            bf.put(buf, 0)
            self.fail("Expected IllegalArgumentException putting small buffer")

        except ValueError as e:

            # expected

        data = bytearray(BUFFER_SIZE - 1)
        buf = DataBuffer(data)

        for i in range(len(data)):
            data[i] = 0xf0
        buf.id = 10

        bf.put(buf, 0)

        for i in range(len(data)):
            data[i] = 0xf1
        buf.id = 11

        bf.put(buf, 1)

        for i in range(len(data)):
            data[i] = 0xf2
        buf.id = 12

        bf.put(buf, 2)

        do_read_test1(bf)

        buf.id = 12
        buf.empty = True

        bf.put(buf, 2)

        do_read_test2(bf)

        return [2]

    def do_read_test1(self, bf):

        buf = DataBuffer()

        try:

            bf.get(buf, 0)
            self.assertEqual(10, buf.id)
            self.assertFalse(buf.empty)
            check_data(buf.data, 0xf0)

            bf.get(buf, 2)
            self.assertEqual(12, buf.id)
            self.assertFalse(buf.empty)
            check_data(buf.data, 0xf2)

            bf.get(buf, 1)
            self.assertEqual(11, buf.id)
            self.assertFalse(buf.empty)
            check_data(buf.data, 0xf1)

        except Exception as e:

            # expected

    def do_read_test2(self, bf):

        buf = DataBuffer()

        try:

            bf.get(buf, 0)
            self.assertEqual(10, buf.id)
            self.assertFalse(buf.empty)
            check_data(buf.data, 0xf0)

            bf.get(buf, 2)
            self.assertEqual(-1, buf.id)
            self.assertTrue(buf.empty)

            bf.get(buf, 1)
            self.assertEqual(11, buf.id)
            self.assertFalse(buf.empty)
            check_data(buf.data, 0xf1)

        except Exception as e:

            # expected

    def check_data(self, data, b):

        self.assertEqual(BUFFER_SIZE, len(data))

def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(LocalBufferFileTest)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)

if __name__ == "__main__":
    main()

```

Note: This code assumes that you have a `DataBuffer` class and a `LocalBufferFile` class, which are not provided in the original Java code. You will need to implement these classes or replace them with equivalent Python implementations.

Also note that this is just one possible translation of the Java code into Python. The resulting Python code may look different from what you would write if you were starting from scratch.