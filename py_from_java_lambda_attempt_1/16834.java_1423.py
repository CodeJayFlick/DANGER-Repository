Here is the equivalent Python code:

```Python
BASE_OUTPUT_PATH = "target" + os.sep
OUTPUT_DATA_DIR = BASE_OUTPUT_PATH + "data" + os.sep
```

Note that in Python, we don't need a `public class` or `package org.apache.iotdb.hadoop.tsfile.constant;`. We also use the built-in `os` module to get the file separator (`os.sep`).