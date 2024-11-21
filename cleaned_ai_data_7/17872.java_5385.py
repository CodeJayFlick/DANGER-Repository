import unittest
from io import StringIO
from contextlib import redirect_stdout
import time

class IoTDBRpcCompressionIT(unittest.TestCase):

    def setUp(self):
        self.rpc_thrift_compression = False
        self.rpc_advanced_compression = False

    def tearDown(self):
        pass

    @unittest.skip("Not implemented")
    def test_no_rpc_compression(self):
        with open('iotdb.log', 'w') as f:
            with redirect_stdout(f):
                do_something()

    @unittest.skip("Not implemented")
    def test_rpc_thrift_compression(self):
        self.rpc_thrift_compression = True
        try:
            with open('iotdb.log', 'w') as f:
                with redirect_stdout(f):
                    do_something()
        finally:
            self.rpc_thrift_compression = False

    @unittest.skip("Not implemented")
    def test_rpc_advanced_compression(self):
        self.rpc_advanced_compression = True
        try:
            with open('iotdb.log', 'w') as f:
                with redirect_stdout(f):
                    do_something()
        finally:
            pass

    @unittest.skip("Not implemented")
    def test_both_rpc_compression(self):
        self.rpc_thrift_compression = True
        self.rpc_advanced_compression = True
        try:
            with open('iotdb.log', 'w') as f:
                with redirect_stdout(f):
                    do_something()
        finally:
            pass

def do_something():
    # your code here
    print("do something")

if __name__ == '__main__':
    unittest.main()

