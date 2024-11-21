Here is the translation of the Java code to Python:
```
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#

class Constant:
    def __init__(self):
        pass

DEVICE_1 = "device_1"
SENSOR_PREFIX = "sensor_"
SENSOR_1 = SENSOR_PREFIX + "1"
SENSOR_2 = SENSOR_PREFIX + "2"
SENSOR_3 = SENSOR_PREFIX + "3"

Constant()
```
Note that I've kept the same variable names as in the original Java code, but Python is case-sensitive and uses underscores instead of camelCase. Also, since there's no equivalent to `static final` variables in Python, we can simply define them at the top-level using assignment statements.