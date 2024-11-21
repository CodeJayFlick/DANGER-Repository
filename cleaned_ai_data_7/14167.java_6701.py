import os
import unittest
from tempfile import TemporaryDirectory
from io import StringIO

class SimpleFileWriterTest(unittest.TestCase):

    def setUp(self):
        self.test_folder = TemporaryDirectory()

    def test_writer_not_null(self):
        temp_file_path = os.path.join(self.test_folder.name, 'temp.txt')
        with open(temp_file_path, 'w') as f:
            pass
        writer = SimpleFileWriter(temp_file_path)
        self.assertIsNotNone(writer)

    def test_creates_non_existent_file(self):
        non_existing_file_path = os.path.join(self.test_folder.name, 'non-existing-file.txt')
        if not os.path.exists(non_existing_file_path):
            with open(non_existing_file_path, 'w') as f:
                pass
        writer = SimpleFileWriter(non_existing_file_path)
        self.assertTrue(os.path.exists(non_existing_file_path))

    def test_contents_are_written_to_file(self):
        test_message = "Test message"
        temp_file_path = os.path.join(self.test_folder.name, 'temp.txt')
        with open(temp_file_path, 'w') as f:
            f.write(test_message)
        writer = SimpleFileWriter(temp_file_path)
        self.assertEqual(writer.read(), test_message)

    def test_ripples_io_exception_occurred_while_writing(self):
        message = "Some error"
        try:
            temp_file_path = os.path.join(self.test_folder.name, 'temp.txt')
            with open(temp_file_path, 'w') as f:
                raise IOError(message)
        except IOError as e:
            self.assertEqual(str(e), message)

class SimpleFileWriter:

    def __init__(self, file_path):
        self.file_path = file_path

    def write(self, content):
        with open(self.file_path, 'w') as f:
            f.write(content)

    def read(self):
        try:
            with open(self.file_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
