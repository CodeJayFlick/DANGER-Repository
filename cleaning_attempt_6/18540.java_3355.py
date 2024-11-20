import logging
from urllib.parse import urlparse

class UrlPathValidator:
    DEFAULT_ERROR_CODE = 404
    PARAM_INVALID_STATUS_CODE = "invalid_status_code"

    def __init__(self):
        self.invalid_status_code = self.DEFAULT_ERROR_CODE
        self.log = logging.getLogger(__name__)

    def init(self, filter_config=None):
        if not filter_config:
            return

        invalid_status_code_param = filter_config.get(PARAM_INVALID_STATUS_CODE)
        try:
            self.invalid_status_code = int(invalid_status_code_param)
        except ValueError as e:
            self.log.error("Could not parse status code from filter config", e)

    def do_filter(self, servlet_request, servlet_response, filter_chain):
        request_path = urlparse(servlet_request.url).path
        if not request_path:
            self.set_error_response(servlet_response)
            return

        try:
            parsed_uri = urlparse(request_path)
        except ValueError as e:
            self.log.error("Invalid uri path in do_filter", e)
            self.set_error_response(servlet_response)
            return

        slash_count = 0
        dot2_count = 0
        for segment in parsed_uri.path.split('/'):
            if segment == '..':
                dot2_count += 1
            elif segment:
                slash_count += 1

        if dot2_count > 0 and (slash_count - len(parsed_uri.path.split('//')) - 1) <= dot2_count:
            self.set_error_response(servlet_response)
            return

        filter_chain.do_filter(servlet_request, servlet_response)

    def destroy(self):
        pass

    def get_invalid_status_code(self):
        return self.invalid_status_code

    def set_error_response(self, resp):
        resp.status = self.invalid_status_code

    @staticmethod
    def count_strings(needle, haystack):
        cur_index = 0
        string_count = 0

        while True:
            cur_index = haystack.find(needle, cur_index)
            if cur_index == -1:
                break
            cur_index += 1
            string_count += 1

        return string_count


# Example usage:

filter_config = {"invalid_status_code": "500"}
validator = UrlPathValidator()
validator.init(filter_config)

servlet_request = None
servlet_response = None
filter_chain = None

validator.do_filter(servlet_request, servlet_response, filter_chain)
