# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import http.client as client

class ResponseFilter:
    """ Filter evaluated post call. The connection, its response streams and response code are available
        to the filter."""
    
    def __init__(self):
        pass
    
    def filter(self, con: dict) -> None:
        # Add your logic here
        pass


# Usage example:

response_filter = ResponseFilter()
con = {"connection": "example", "code": 200}
response_filter.filter(con)
