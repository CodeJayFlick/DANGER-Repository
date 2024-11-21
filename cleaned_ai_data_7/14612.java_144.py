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
