Here is the equivalent Python code:

```Python
import iotdb_python as IoTDBClient
from pyflink import FlinkSession
from pyflink.datastream.functions.util import simple_name
from pyflink.datastream.stream_execution_environment import StreamExecutionEnvironment
from typing import List, Dict

LOCAL_HOST = "127.0.0.1"
ROOT_SG1_D1_S1 = "root.sg1.d1.s1"
ROOT_SG1_D1 = "root.sg1.d1"

def prepare_data():
    client = IoTDBClient.Session(LOCAL_HOST, 6667, 'root', 'root')
    try:
        client.open(False)
        client.set_storage_group("root.sg1")
        
        if not client.check_timeseries_exists(ROOT_SG1_D1_S1):
            client.create_timeseries(
                ROOT_SG1_D1_S1,
                IoTDBClient.TSDataType.INT64,
                IoTDBClient.TSEncoding.RLE,
                IoTDBClient.CompressionType.SNAPPY
            )
            
            measurements = ["s1", "s2", "s3"]
            types = [IoTDBClient.TSDataType.INT64] * 3
            
            for time in range(100):
                values = [1, 2, 3]
                client.insert_record(ROOT_SG1_D1, time, measurements, types, values)
    except IoTDBClient.StatementExecutionException as e:
        if e.status_code != IoTDBClient.TSStatusCode.PATH_ALREADY_EXIST_ERROR.status_code:
            raise e

def main():
    prepare_data()
    
    env = FlinkSession.get_execution_environment()
    io_tdb_source_options = {
        'host': LOCAL_HOST,
        'port': 6667,
        'username': 'root',
        'password': 'root',
        'query': f"select s1 from {ROOT_SG1_D1} align by device"
    }
    
    source = IoTDBSource(io_tdb_source_options)
    env.add_source(source).name("sensor-source").print().set_parallelism(2)
    env.execute()

if __name__ == "__main__":
    main()
```

Please note that this code is not tested and might require some adjustments to work correctly. Also, the `IoTDBSource` class needs to be implemented in Python as it's a custom Java class.