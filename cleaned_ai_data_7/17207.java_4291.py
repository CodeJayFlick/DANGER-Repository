import logging
from typing import List

class PublishHandler:
    def __init__(self, config):
        self.payload_format = PayloadFormatter(config.get_mqtt_payload_formatter())
        try:
            self.executor = PlanExecutor()
        except Exception as e:
            raise RuntimeError(str(e))

    @property
    def id(self) -> str:
        return "iotdb-mqtt-broker-listener"

    def on_publish(self, msg):
        client_id = msg.client_id
        payload = msg.payload
        topic = msg.topic_name
        username = msg.username
        qos = msg.qos

        logging.debug(
            f"Receive publish message. clientId: {client_id}, username: {username}, qos: {qos}, topic: {topic}, payload: {payload}"
        )

        events = self.payload_format.format(payload)
        if not events:
            return

        for event in events:
            if not event:
                continue
            plan = InsertRowPlan()
            plan.time = event.timestamp
            plan.measurements = list(event.measurement.values())
            plan.values = [value for value in event.value]
            plan.data_types = [TSDataType] * len(plan.values)
            plan.need_infer_type = True

            try:
                plan.prefix_path = PartialPath(event.device)
                status = self.execute_non_query(plan)
            except Exception as e:
                logging.warn(
                    f"meet error when inserting device {event.device}, measurements {list(event.measurement.keys())}, at time {event.timestamp} because {str(e)}"
                )

            logging.debug(f"Event process result: {status}")

    def execute_non_query(self, plan):
        if IoTDBDescriptor().get_instance().config.read_only:
            raise QueryProcessException(
                "Current system mode is read-only, does not support non-query operation"
            )
        return self.executor.process_non_query(plan)


class PayloadFormatter:
    pass


class PlanExecutor:
    def process_non_query(self, plan):
        # Your implementation here
        pass

class InsertRowPlan:
    @property
    def time(self) -> int:
        return 0

    @time.setter
    def time(self, value: int):
        self._time = value

    @property
    def measurements(self) -> List[str]:
        return []

    @measurements.setter
    def measurements(self, value: List[str]):
        self._measurements = value

    @property
    def values(self) -> List[object]:
        return []

    @values.setter
    def values(self, value: List[object]):
        self._values = value

    @property
    def data_types(self) -> List['TSDataType']:
        return []

    @data_types.setter
    def data_types(self, value: List['TSDataType']):
        self._data_types = value

    @property
    def need_infer_type(self) -> bool:
        return False

    @need_infer_type.setter
    def need_infer_type(self, value: bool):
        self._need_infer_type = value


class TSDataType:
    pass
