Here is the translation of the Java code to Python:
```
# Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

import thrift.tconfiguration as TConfiguration
from thrift import RpcUtils

default_t_configuration = TConfiguration.TConfiguration(
    RpcUtils.THRESHOLD_FRAME_MAX_SIZE + 4,
    RpcUtils.THRESHOLD_FRAME_MAX_SIZE,
    TConfiguration.DEFAULT_RECURSION_DEPTH)
```
Note that I've removed the unnecessary comments and package declarations, as they are not relevant to the Python code.