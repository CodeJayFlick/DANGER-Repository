import json

class NessieHttpResponseFilter:
    def __init__(self, mapper):
        self.mapper = mapper

    def filter(self, con):
        try:
            ResponseCheckFilter.check_response(con, self.mapper)
        except Exception as e:
            raise HttpClientException(e)  # pass up invalid response exception as untyped exception
