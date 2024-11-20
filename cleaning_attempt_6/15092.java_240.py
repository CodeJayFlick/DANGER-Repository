import unittest
from unittest.mock import patch

class TenantTest(unittest.TestCase):

    @patch('com.iluwatar.throttling.Tenant')
    def test_constructor(self, mock_tenant):
        with self.assertRaises(ValueError):
            tenant = mock_tenant("FailTenant", -1, None)
