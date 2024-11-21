Here is the equivalent Python code:

```Python
import unittest

class RequestReaderTest(unittest.TestCase):

    ORDERS_URL = "/orders"
    BASE_PATH_MAPPING = "svc1"

    def setUp(self):
        self.request_reader = AwsProxyHttpServletRequestReader()

    def test_default_config_do_not_strip_base_path(self):
        config = ContainerConfig().default_config()
        self.assertFalse(config.strip_base_path)
        self.assertIsNone(config.service_base_path)

    def test_set_service_base_path_add_slashes(self):
        config = ContainerConfig()
        config.set_service_base_path(BASE_PATH_MAPPING)
        self.assertEqual("/" + BASE_PATH_MAPPING, config.get_service_base_path())

        config.set_service_base_path(BASE_PATH_MAPPING + "/")
        self.assertEqual("/" + BASE_PATH_MAPPING, config.get_service_base_path())

    def test_request_reader_strip_base_path(self):
        config = ContainerConfig().default_config()
        request_path = "/" + BASE_PATH_MAPPING + ORDERS_URL

        final_path = self.request_reader.strip_base_path(request_path, config)
        self.assertIsNotNone(final_path)
        self.assertEqual(request_path, final_path)

        config.set_strip_base_path(True)
        config.set_service_base_path(BASE_PATH_MAPPING)
        final_path = self.request_reader.strip_base_path(request_path, config)
        self.assertIsNotNone(final_path)
        self.assertEqual(ORDERS_URL, final_path)

        final_path = self.request_reader.strip_base_path(ORDERS_URL, config)
        self.assertIsNotNone(final_path)
        self.assertEqual(ORDERS_URL, final_path)

    def test_request_reader_double_base_path(self):
        config = ContainerConfig().default_config()
        config.set_strip_base_path(True)
        config.set_service_base_path(BASE_PATH_MAPPING)

        final_path = self.request_reader.strip_base_path("/" + BASE_PATH_MAPPING + "/" + BASE_PATH_MAPPING, config)
        self.assertIsNotNone(final_path)
        self.assertEqual("/" + BASE_PATH_MAPPING, final_path)

        final_path = self.request_reader.strip_base_path("/custom/" + BASE_PATH_Mapping, config)
        self.assertIsNotNone(final_path)
        self.assertEqual("/custom/" + BASE_PATH_MAPPING, final_path)

        final_path = self.request_reader.strip_base_path(BASE_PATH_MAPPING, config)
        self.assertIsNotNone(final_path)
        # the request path does not start with a "/", the comparison in the method should fail
        # and nothing should get replaced
        self.assertEqual(BASE_PATH_MAPPING, final_path)


if __name__ == '__main__':
    unittest.main()
```

Note: This code assumes that `AwsProxyHttpServletRequestReader` is equivalent to the Java class of the same name.