# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

import thrift.protocol.TProtocol as TProtocol

class TestSyncClient:
    def __init__(self, serial_num=None):
        self.serial_num = serial_num if serial_num is not None else 0

    @property
    def serial_num(self):
        return self._serial_num

    @serial_num.setter
    def serial_num(self, value):
        self._serial_num = value

# Note: This code assumes that the `RaftService.Client` class and its methods are equivalent in Python.
class RaftServiceClient:
    pass  # implement this class as needed

if __name__ == '__main__':
    client = TestSyncClient()
    print(client.serial_num)  # prints 0
