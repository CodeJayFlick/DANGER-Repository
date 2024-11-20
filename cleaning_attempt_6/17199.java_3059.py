# Licensed under Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class MonitorConstants:
    INT64 = "INT64"
    PATH_SEPARATOR = "."
    
    STAT_STORAGE_GROUP_NAME = "root.stats"
    STAT_STORAGE_GROUP_ARRAY = ["root", "stats"]
    STAT_GLOBAL_ARRAY = ["root", "stats", "\"global\""]

    class StatMeasurementConstants:
        TOTAL_POINTS = ("TOTAL_POINTS",)
        TOTAL_REQ_SUCCESS = ("TOTAL_REQ_SUCCESS",)
        TOTAL_REQ_FAIL = ("TOTAL_REQ_FAIL",)

        def __init__(self, measurement):
            self.measurement = measurement

        @property
        def measurement(self):
            return self.measurement


# Usage example:
monitor_constants = MonitorConstants()
print(monitor_constants.INT64)  # Output: INT64
print(monitor_constants.STAT_STORAGE_GROUP_NAME)  # Output: root.stats
stat_measurement_constant = monitor_constants.StatMeasurementConstants.TOTAL_POINTS[0]
print(stat_measurement_constant)  # Output: TOTAL_POINTS
