Here is the equivalent Python code:

```Python
import unittest
from ghidra.util import SystemUtilities


class SSHJoinModelForGDBSessionLauncherTest(unittest.TestCase):

    def setUp(self):
        self.assertFalse(SystemUtilities.is_in_testing_batch_mode())

    def test_model_host(self):
        return SshJoinGdbModelHost()


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalents for Java's `@Before` and `@Category`, so I've replaced them with a setup method (`setUp`) which is called before each test, and the category has been removed as it seems to be related to testing frameworks.