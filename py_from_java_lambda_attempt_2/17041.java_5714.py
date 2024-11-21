Here is the translation of the given Java code into equivalent Python:

```Python
import logging

class TriggerEngine:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def fire(event: dict, insert_row_plan: dict) -> None:
        measurement_mnodes = insert_row_plan.get('measurement_mnodes', [])
        size = len(measurement_mnodes)

        timestamp = insert_row_plan.get('time')
        values = insert_row_plan.get('values')

        for i in range(size):
            mnode = measurement_mnodes[i]
            if not mnode:
                continue

            executor = mnode.get('trigger_executor', None)
            if not executor:
                continue

            try:
                executor.fire_if_activated(event, timestamp, values[i])
            except Exception as e:
                self.logger.error(f"Failed to fire trigger {mnode['name']}({mnode['class_name']}) when inserting data: {e}")

    @staticmethod
    def fire(event: dict, insert_tablet_plan: dict, fire_position: int) -> None:
        measurement_mnodes = insert_tablet_plan.get('measurement_mnodes', [])
        size = len(measurement_mnodes)

        timestamps = insert_tablet_plan.get('times')
        columns = insert_tablet_plan.get('columns')

        if fire_position != 0:
            timestamps = timestamps[fire_position:]
            columns = columns[fire_position:]

        for i in range(size):
            mnode = measurement_mnodes[i]
            if not mnode:
                continue

            executor = mnode.get('trigger_executor', None)
            if not executor:
                continue

            try:
                executor.fire_if_activated(event, timestamps, columns[i])
            except Exception as e:
                self.logger.error(f"Failed to fire trigger {mnode['name']}({mnode['class_name']}) when inserting data: {e}")

    @staticmethod
    def drop(measurement_mnode: dict) -> None:
        executor = measurement_mnode.get('trigger_executor', None)
        if not executor:
            return

        try:
            TriggerRegistrationService().deregister(DropTriggerPlan(measurement_mnode['name']))
        except Exception as e:
            self.logger.error(f"Failed to deregister trigger {measurement_mnode['name']} when deleting timeseries: {e}")

    @staticmethod
    def drop(measurement_nodes: list) -> None:
        for node in measurement_nodes:
            TriggerEngine.drop(node)

# Usage example:

trigger_engine = TriggerEngine()

event = {'type': 'insert', 'data': [1, 2, 3]}
row_plan = {'measurement_mnodes': [{'name': 'node1'}, {'name': 'node2'}], 'time': 1643723400, 'values': ['value1', 'value2']}
TriggerEngine.fire(event, row_plan)

tablet_plan = {'measurement_mnodes': [{'name': 'node3'}, {'name': 'node4'}], 'times': [1643723410, 1643723420], 'columns': ['column1', 'column2'], 'fire_position': 1}
TriggerEngine.fire({'type': 'insert_tablet'}, tablet_plan, 1)

measurement_node = {'name': 'node5'}
TriggerEngine.drop(measurement_node)
```

This Python code is a direct translation of the given Java code. It uses dictionaries to represent data structures and methods like `get` for accessing dictionary values. The `logging` module from Python's standard library has been used for logging purposes, similar to how it was done in the original Java code.