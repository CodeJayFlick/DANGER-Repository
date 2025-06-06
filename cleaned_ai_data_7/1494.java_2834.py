# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

class InVmModelForGdbScenarioMemoryTest(unittest.TestCase):
    def test_model_host(self):
        from agent.gdb.model import InVmGdbModelHost
        self.assertEqual(InVmGdbModelHost().__class__.__name__, "InVmGdbModelHost")

if __name__ == "__main__":
    unittest.main()
