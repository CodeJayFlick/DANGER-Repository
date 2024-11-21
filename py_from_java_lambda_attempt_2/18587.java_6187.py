Here is the translation of the Java code into Python:

```Python
import unittest
from unittest.mock import Mock

class UrlPathValidatorTest(unittest.TestCase):

    def test_init_no_config_sets_default_status_code(self):
        path_validator = UrlPathValidator()
        try:
            path_validator.init(None)
            self.assertEqual(UrlPathValidator.DEFAULT_ERROR_CODE, path_validator.get_invalid_status_code())
        except Exception as e:
            print(str(e))
            self.fail("Unexpected exception")

    def test_init_with_config_sets_correct_status_code(self):
        path_validator = UrlPathValidator()
        params = {"invalid-status-code": "401"}
        filter_config = Mock(filter_name=None, servlet_context=None)
        for key, value in params.items():
            setattr(filter_config, f"get{key.replace('-', '_')}", lambda: value)

        try:
            path_validator.init(filter_config)
            self.assertEqual(401, path_validator.get_invalid_status_code())
        except Exception as e:
            print(str(e))
            self.fail("Unexpected exception")

    def test_init_with_wrong_config_sets_default_status_code(self):
        path_validator = UrlPathValidator()
        params = {"invalid-status-code": "hello"}
        filter_config = Mock(filter_name=None, servlet_context=None)
        for key, value in params.items():
            setattr(filter_config, f"get{key.replace('-', '_')}", lambda: value)

        try:
            path_validator.init(filter_config)
            self.assertEqual(UrlPathValidator.DEFAULT_ERROR_CODE, path_validator.get_invalid_status_code())
        except Exception as e:
            print(str(e))
            self.fail("Unexpected exception")

    def test_do_filter_invalid_relative_path_uri_sets_default_status_code(self):
        req = AwsProxyHttpServletRequest(AwsProxyRequestBuilder("../..", "GET").build(), None, None)
        resp = AwsHttpServletResponse(req, None)
        path_validator = UrlPathValidator()
        try:
            path_validator.init(None)
            path_validator.do_filter(req, resp, None)
            self.assertEqual(UrlPathValidator.DEFAULT_ERROR_CODE, resp.status_code)
        except Exception as e:
            print(str(e))
            self.fail("Unexpected exception")

    def test_do_filter_invalid_uri_sets_default_status_code(self):
        req = AwsProxyHttpServletRequest(AwsProxyRequestBuilder("wonkyprotocol://˝Ó#\u0009", "GET").build(), None, None)
        resp = AwsHttpServletResponse(req, None)
        path_validator = UrlPathValidator()
        try:
            path_validator.init(None)
            path_validator.do_filter(req, resp, None)
            self.assertEqual(UrlPathValidator.DEFAULT_ERROR_CODE, resp.status_code)
        except Exception as e:
            print(str(e))
            self.fail("Unexpected exception")


class FilterConfig(Mock):
    def get_init_parameter_names(self):
        return iter(list(self.__dict__.keys()))


if __name__ == "__main__":
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest.TestCase` class and define methods starting with "test_" as test cases.