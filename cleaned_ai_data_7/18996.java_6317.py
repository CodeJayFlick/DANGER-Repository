import logging

class StopTask:
    def __init__(self):
        self.application = None
        self.restore_system_props = {}

    @property
    def application(self):
        return self._application

    @application.setter
    def set_quarkus_application(self, quarkus_app):
        self._application = quarkus_app

    def stop(self):
        if not self.application:
            logging.debug("No application found.")
            return

        try:
            self.application.close()
            logging.info("Quarkus application stopped.")
        except Exception as e:
            raise RuntimeError(e)

        finally:
            self.application = None
            for k, v in self.restore_system_props.items():
                if v is not None:
                    import os
                    os.environ[k] = v
                else:
                    del os.environ[k]

if __name__ == "__main__":
    pass  # This code doesn't have a main function, so we don't need to do anything here.
