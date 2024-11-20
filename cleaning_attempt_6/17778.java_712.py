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
