import unittest

class ServiceAmbassadorTest(unittest.TestCase):

    def test(self):
        result = ServiceAmbassador().do_remote_function(10)
        self.assertTrue(result == 100 or result == RemoteServiceStatus.FAILURE.get_remote_service_status_value())

if __name__ == '__main__':
    unittest.main()
