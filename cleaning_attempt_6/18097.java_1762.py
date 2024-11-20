import os
from unittest import TestCase


class HDFSInputTest(TestCase):

    def setUp(self):
        self.folder = 'test-output/HDFSInputTest'
        if not os.path.exists(self.folder):
            os.makedirs(self.folder)
        path = os.path.join(self.folder, 'test.tsfile')
        with open(path, 'w'):
            pass
        self.in = HDFSInput(path)

    def tearDown(self):
        try:
            self.in.close()
        except AttributeError:  # in case it's not a file-like object
            pass
        if os.path.exists(self.folder):
            for root, dirs, files in os.walk(self.folder):
                for f in files:
                    os.remove(os.path.join(root, f))
                for d in dirs:
                    shutil.rmtree(os.path.join(root, d))

    def test_read1(self):
        size = 500
        buffer = bytearray(size)
        self.assertEqual(len(buffer), self.in.read(buffer))

    def test_read2(self):
        size = 500
        pos = 20
        buffer = bytearray(size)
        self.assertEqual(len(buffer), self.in.read(buffer, pos))
