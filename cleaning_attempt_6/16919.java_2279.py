import logging

class IoTDBDefaultThreadExceptionHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def uncaught_exception(self, t, e):
        self.logger.error("Exception in thread %s-%d: %s", t.name, t.ident, str(e))
