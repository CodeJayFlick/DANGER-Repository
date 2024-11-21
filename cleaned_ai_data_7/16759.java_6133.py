class Constant:
    def __init__(self):
        pass

CONNECTION_NAME = "RabbitMQ-Connection"
RABBITMQ_CONSUMER_QUEUE = "IoTDB_Topic_Queue"
RABBITMQ_CONSUMER_TAG = "IoTDB_ CONSUMER_TAG"
TOPIC = "RabbitMQ-Test"
IOTDB_CONNECTION_HOST = "localhost"
IOTDB_CONNECTION_PORT = 6667
IOTDB_CONNECTION_USER = "root"
IOTDB_CONNECTION_PWD = "root"
STORAGE_GROUP = "root.vehicle"

PLAIN = "PLAIN"
SNAPPY = "SNAPPY"

TIMESERIESLIST = [
    ["root.vehicle.d0.s0", "INT32", PLAIN, SNAPPY],
    ["root.vehicle.d0.s1", "TEXT", PLAIN, SNAPPY],
    ["root.vehicle.d1.s2", "FLOAT", PLAIN, SNAPPY],
    ["root.vehicle.d1.s3", "BOOLEAN", PLAIN, SNPPPY],
    ["root.test.d0.s0", "INT32", PLAIN, SNAPPY],
    ["root.test.d0.s1", "TEXT", PLAIN, SNAPPY],
    ["root.test.d1.s0", "INT32", PLAIN, SNAPPY]
]

ALL_DATA = [
    "root.vehicle.d0,10,s0,INT32,100",
    "root.vehicle.d0,12,s0:s1,INT32:TEXT,101:'employeeId102'",
    "root.vehicle.d0,19,s1,TEXT,'employeeId103'",
    "root.vehicle.d1,11,s2,FLOAT,104.0",
    "root.vehicle.d1,15,s2:s3,FLOAT:BOOLEAN,105.0:true",
    "root.vehicle.d1,17,s3,BOOLEAN,false",
    "root.vehicle.d0,20,s0,INT32,1000",
    "root.vehicle.d0,22,s0:s1,INT32:TEXT,1001:'employeeId1002'",
    "root.vehicle.d0,29,s1,TEXT,'employeeId1003'",
    "root.vehicle.d1,21,s2,FLOAT,1004.0",
    "root.vehicle.d1,25,s2:s3,FLOAT:BOOLEAN,1005.0:true",
    "root.vehicle.d1,27,s3,BOOLEAN,true",
    "root.test.d0,10,s0,INT32,106",
    "root.test.d0,14,s0:s1,INT32:TEXT,107:'employeeId108'",
    "root.test.d0,16,s1,TEXT,'employeeId109'",
    "root.test.d1,1,s0,INT32,110",
    "root.test.d0,30,s0,INT32,1006",
    "root.test.d0,34,s0:s1,INT32:TEXT,1007:'employeeId1008'",
    "root.test.d0,36,s1,TEXT,'employeeId1090'",
    "root.test.d1,10,s0,INT32,1100"
]
