Here is the equivalent Python code:

```Python
import time
from datetime import datetime

class MemtableBenchmark:
    deviceId = "d0"
    numOfMeasurement = 10000
    numOfPoint = 1000

    measurementId = [f"m{i}" for i in range(numOfMeasurement)]
    ts_data_type = 'int64'

    def __init__(self):
        pass

    @staticmethod
    def main():
        start_time = time.time()
        
        # cpu not locality
        for _ in range(numOfPoint):
            for j in range(numOfMeasurement):
                mem_table.write(deviceId, 
                                UnaryMeasurementSchema(measurementId[j], ts_data_type), 
                                datetime.now().timestamp(), str(int(datetime.now().timestamp())))
                
        end_time = time.time()
        
        print(f"Num of time series: {numOfMeasurement}, "
              f"Num of points for each time series: {numOfPoint}, "
              f"The total time: {(end_time - start_time) * 1000} ms.")

if __name__ == "__main__":
    MemtableBenchmark.main()
```

Please note that Python does not have direct equivalent to Java's `TSDataType` and `TSEncoding`. I've replaced them with a string 'int64' as it seems you are using this type for integer values. Also, the `UnaryMeasurementSchema` class is also missing in Python code.