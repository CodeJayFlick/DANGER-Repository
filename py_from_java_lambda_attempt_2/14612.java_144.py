Here is the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import unittest
from domainapp.integtests.bootstrap import SimpleAppSystemInitializer
from org.junit import BeforeClass, TestCase


class SimpleAppIntegTest(TestCase):
    @classmethod
    def setUpClass(cls):
        SimpleAppSystemInitializer.init_isft()
        
        # instantiating will install onto ThreadLocal
        ScenarioExecutionForIntegration()

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@BeforeClass` annotation. Instead, we use the `setUpClass()` method which is a classmethod and gets called once before any test methods in this class are executed.

Also, there is no direct equivalent of Java's `IntegrationTestAbstract`. It seems like it was used to provide some common functionality for integration tests. In Python, you would typically create your own base class or use an existing one (like unittest.TestCase) and override the necessary methods as needed.