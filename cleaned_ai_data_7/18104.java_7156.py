# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#

import unittest

class ThreeNodeCluster2IT(unittest.TestCase):
    def get_write_rpc_ip(self):
        return self.get_container().get_service_host("iotdb-server_2", 6667)

    def get_write_rpc_port(self):
        return self.get_container().get_service_port("iotdb-server_2", 6667)
