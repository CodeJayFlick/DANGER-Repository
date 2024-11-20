Here is the translation of the Java code into Python:

```Python
import json
from datetime import datetime, timezone
from typing import List, Tuple

class DatabaseConnectController:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.gson = json.dumps

    @cross_origin()
    def test_data_connection(self, request: HttpRequest, response: HttpResponse) -> None:
        self.logger.info("Connection is ok now!")
        writer = response.get_writer()
        writer.print("I have sent a message.")

    def metric_find_query(self, request: HttpRequest, response: HttpResponse) -> str:
        root = json.dumps({"columns": []})
        try:
            columns_name = database_connect_service.get_meta_data()
            for column in sorted(columns_name):
                root["columns"].append(column)
        except Exception as e:
            self.logger.error("Failed to get metadata", e)

        return root

    def query(self, request: HttpRequest, response: HttpResponse) -> str:
        target_str = "target"
        try:
            json_object = self.get_request_body_json(request)
            if not json_object:
                return None
            time_range = self.get_time_from_and_to(json_object)
            array = json_object["targets"]
            result = []
            for i in range(array.size()):
                object_ = array[i]
                target = object_[target_str].get()
                type_ = self.get_json_type(json_object)
                if not hasattr(object_, "has"):
                    return "[]"
                obj = {"target": target}
                if type_.equals("table"):
                    set_json_table(obj, target, time_range)
                elif type_.equals("timeserie"):
                    set_json_timeseries(obj, target, time_range)
                result.append(obj)

            self.logger.info("query finished")
            return json.dumps(result)
        except Exception as e:
            self.logger.error("/query failed", e)

    def get_request_body_json(self, request: HttpRequest) -> dict:
        try:
            br = BufferedReader(request.get_reader())
            sb = StringBuilder()
            line
            while (line := br.read_line()) is not None:
                sb.append(line)
            return json.loads(sb.toString())
        except IOException as e:
            self.logger.error("get_request_body_json failed", e)

    def get_time_from_and_to(self, json_object: dict) -> Tuple[datetime, datetime]:
        obj = json_object["range"]
        from_ = datetime.fromisoformat(obj["from"].get()).astimezone(timezone.utc)
        to = datetime.fromisoformat(obj["to"].get()).astimezone(timezone.utc)
        return (from_, to)

    def set_json_table(self, obj: dict, target: str, time_range: Tuple[datetime, datetime]) -> None:
        time_values = database_connect_service.query_series(target, time_range)
        columns = []
        column = {"text": "Time", "type": "time"}
        columns.append(column)

        value = {"text": "Number", "type": "number"}
        columns.append(value)

        obj["columns"] = json.dumps(columns)
        values = []
        for tv in time_values:
            value_ = {"value": tv.value, "time": tv.time}
            values.append(json.dumps(value_))

        obj["values"] = json.dumps(values)

    def set_json_timeseries(self, obj: dict, target: str, time_range: Tuple[datetime, datetime]) -> None:
        time_values = database_connect_service.query_series(target, time_range)
        logger.info("query size: {}".format(len(time_values)))

        data_points = []
        for tv in time_values:
            value_ = {"value": json.dumps(tv.value), "time": tv.time}
            data_points.append(json.dumps(value_))

        obj["datapoints"] = json.dumps(data_points)

    def get_json_type(self, json_object: dict) -> str:
        array = json_object["targets"]
        object_ = array[0]
        return object_.get("type")
```

Note that this code assumes you have a `database_connect_service` class with methods for getting metadata and querying series. It also uses the `logging` module to log messages, which is not included in Python's standard library so it needs to be installed separately (`pip install logging`).