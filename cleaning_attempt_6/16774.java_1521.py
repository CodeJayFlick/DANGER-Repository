import requests
from datetime import datetime as dt

class AlertingExample:
    def __init__(self):
        self.alert_manager_handler = None
        self.alert_manager_configuration = None
        self.alertname = ""
        self.labels = {}
        self.annotations = {}

    def on_create(self, attributes):
        if not self.alert_manager_handler:
            self.alert_manager_handler = requests.Session()
            self.alert_manager_configuration = {"url": "http://127.0.0.1:9093/api/v2/alerts"}
            self.alertname = "alert_test"
            self.labels["series"] = "root.ln.wf01.wt01.temperature"
            self.labels["value"] = ""
            self.labels["severity"] = ""

        self.annotations["summary"] = "high temperature"
        self.annotations["description"] = "{{.alertname}}: {{.series}} is {{.value}}"

    def on_drop(self):
        if self.alert_manager_handler:
            self.alert_manager_handler.close()

    def on_start(self):
        if not self.alert_manager_handler:
            self.on_create(None)

    def on_stop(self):
        if self.alert_manager_handler:
            self.alert_manager_handler.close()

    def fire(self, timestamp: int, value: float) -> float:
        if value > 100.0:
            self.labels["value"] = str(value)
            self.labels["severity"] = "critical"
            alert_event = {"alertname": self.alertname, "labels": self.labels, "annotations": self.annotations}
            self.alert_manager_handler.post("http://127.0.0.1:9093/api/v2/alerts", json=alert_event)

        elif value > 50.0:
            self.labels["value"] = str(value)
            self.labels["severity"] = "warning"
            alert_event = {"alertname": self.alertname, "labels": self.labels, "annotations": self.annotations}
            self.alert_manager_handler.post("http://127.0.0.1:9093/api/v2/alerts", json=alert_event)

        return value

    def fire_batch(self, timestamps: list[int], values: list[float]) -> list[float]:
        for timestamp, value in zip(timestamps, values):
            if value > 100.0:
                self.labels["value"] = str(value)
                self.labels["severity"] = "critical"
                alert_event = {"alertname": self.alertname, "labels": self.labels, "annotations": self.annotations}
                self.alert_manager_handler.post("http://127.0.0.1:9093/api/v2/alerts", json=alert_event)

            elif value > 50.0:
                self.labels["value"] = str(value)
                self.labels["severity"] = "warning"
                alert_event = {"alertname": self.alertname, "labels": self.labels, "annotations": self.annotations}
                self.alert_manager_handler.post("http://127.0.0.1:9093/api/v2/alerts", json=alert_event)

        return values
