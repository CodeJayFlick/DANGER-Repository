# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class TracingConstant:
    def __init__(self):
        pass

    ACTIVITY_START_EXECUTE = "%s: Start to execute statement"
    ACTIVITY_PARSE_SQL = "Parse SQL to physical plan"
    ACTIVITY_CREATE_DATASET = "Create and cache dataset"
    ACTIVITY_REQUEST_COMPLETE = "Request complete"

tracing_constant = TracingConstant()
