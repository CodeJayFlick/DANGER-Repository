import influxdb.exceptions as InfluxDBException
from typing import Dict, List, Tuple

class MetaManager:
    def __init__(self, session_point):
        self.session = Session(session_point.get_host(), 
                                 session_point.get_rpc_port(),
                                 session_point.get_username(),
                                 session_point.get_password())
        
        try:
            self.session.open()
        except Exception as e:
            raise InfluxDBException(str(e))
            
        self.database2measurement2tag_orders: Dict[str, Dict[str, Dict[str, int]]] = {}
        self.recover()

    def recover(self):
        try:
            result = self.session.execute_query_statement("select database_name, measurement_name, tag_name, tag_order from root.TAG_INFO")
            
            while result.has_next():
                fields = list(result.next().get_fields())
                database_name = str(fields[0].value)
                measurement_name = str(fields[1].value)

                if not self.database2measurement2tag_orders.get(database_name):
                    self.database2measurement2tag_orders[database_name] = {}
                    
                tag_orders: Dict[str, int]
                if not self.database2measurement2tag_orders[database_name].get(measurement_name):
                    self.database2measurement2tag_orders[database_name][measurement_name] = {}

                for field in fields:
                    if str(field.value) == "tag_name":
                        tag_name = str(fields[3].value)
                    elif str(field.value) == "tag_order":
                        tag_order = int(str(fields[4].value))
                        
                self.database2measurement2tag_orders[database_name][measurement_name][tag_name] = tag_order
        except Exception as e:
            raise InfluxDBException(str(e))

    def create_database(self, database: str) -> Dict[str, Dict[str, int]]:
        if not self.database2measurement2tag_orders.get(database):
            try:
                self.session.set_storage_group(f"root.{database}")
            except Exception as e:
                raise InfluxDBException(str(e))
            
            return {}
        
    def get_tag_orders_with_auto_creating_schema(self, database: str, measurement: str) -> Dict[str, int]:
        if not self.create_database(database):
            return {}

        return self.database2measurement2tag_orders[database].get(measurement, {})

    def generate_path(self, database: str, measurement: str, tags: dict) -> str:
        tag_key_to_layer_orders = self.get_tag_orders_with_auto_creating_schema(database, measurement)
        
        new_tag_info_records = None
        for key in sorted(tags.keys()):
            if not tag_key_to_layer_orders.get(key):
                if not new_tag_info_records:
                    new_tag_info_records = TagInfoRecords()
                
                new_tag_key_to_layer_orders[tag_key] = len(tag_key_to_layer_orders)
                new_tag_info_records.add(database, measurement, tag_key, len(tag_key_to_layer_orders))
        
        for key in sorted(tags.keys()):
            layer_order_to_tag_keys_in_path[new_tag_key_to_layer_orders[key]] = tags.get(key)

        if new_tag_info_records:
            new_tag_info_records.persist(self.session)
            self.database2measurement2tag_orders[database][measurement] = tag_key_to_layer_orders

        path = f"root.{database}.{measurement}"
        
        for i in range(1, len(tag_key_to_layer_orders) + 1):
            if layer_order_to_tag_keys_in_path.get(i):
                path += f".{tags[layer_order_to_tag_keys_in_path[i]]}"
            else:
                path += f".{InfluxDBConstant.PLACEHOLDER}"

        return path

    def close(self):
        self.session.close()

class Session:
    def __init__(self, host: str, rpc_port: int, username: str, password: str):
        pass
    
    def open(self) -> None:
        pass
    
    def set_storage_group(self, storage_group: str) -> None:
        pass

    def execute_query_statement(self, query: str) -> None:
        pass
