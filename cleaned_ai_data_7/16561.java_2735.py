import logging
from threading import Lock
from typing import Any

class GetDevicesHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.result = None  # type: bytes | None
        self.contact = None  # type: Node | None
        self.lock = Lock()

    def onComplete(self, resp: bytes) -> None:
        self.logger.debug(f"Received devices schema from {self.contact}")
        with self.lock:
            self.result = resp

    def onError(self, exception: Exception) -> None:
        self.logger.warning(f"Cannot get devices schema from {self.contact}, because {exception}")

    def set_response(self, response: Any) -> None:
        self.result = response  # type: bytes | None

    def set_contact(self, contact: Any) -> None:
        self.contact = contact  # type: Node | None
