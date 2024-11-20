# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class UDFPlan:
    """UDF execution plan."""

    def __init__(self):
        pass

    def construct_udf_executors(self, result_columns: list) -> None:
        """
        Build the execution plan of the executors.
        This method will not create any UDF instances, nor
        will it execute user-defined logic.
        """
        # todo: implement this method in Python equivalent to Java's void constructUdfExecutors(List<ResultColumn> resultColumns);

    def finalize_udf_executors(self, query_id: int) -> None:
        """
        Call UDF finalization methods and release computing resources.
        """
        # todo: implement this method in Python equivalent to Java's void finalizeUDFExecutors(long queryId);
