Here is the translation of the Java code into equivalent Python:

```Python
import logging
from typing import Dict, Any

class StartTask:
    def __init__(self):
        pass

    @staticmethod
    def quarkus_start(test_task: str) -> None:
        stop_task = test_task  # assuming this is a string representing the StopTask class
        extension = QuarkusAppExtension()  # assuming this is an object with getPropsProperty and getNativeBuilderImageProperty methods

        props = extension.get_props_property().get()
        if not stop_task.application:  # assuming application attribute exists in StopTask class
            logging.info("Starting Quarkus application.")
            for k, v in extension.get_system_properties().items():
                StartTask.set_system_property(stop_task, k, v)

            try:
                native_builder_image = extension.get_native_builder_image_property().get()
                if not stop_task.quarkus_app.native.builder.image:  # assuming this attribute exists
                    stop_task.quarkus_app.native.builder.image = native_builder_image
            except AttributeError as e:
                logging.error(f"Error setting quarkus app property {e}")

            try:
                log_manager = "org.jboss.logmanager.LogManager"
                if not stop_task.system_properties.get("java.util.logging.manager"):  # assuming this attribute exists
                    stop_task.system_properties["java.util.logging.manager"] = log_manager
            except AttributeError as e:
                logging.error(f"Error setting system property {e}")

            try:
                config_file = StartTask.class.getResource("/org/projectnessie/quarkus/gradle/log4j2-quarkus.xml").toString()
                if not stop_task.system_properties.get("log4j2.configurationFile"):  # assuming this attribute exists
                    stop_task.system_properties["log4j2.configurationFile"] = config_file
            except AttributeError as e:
                logging.error(f"Error setting system property {e}")

            quarkus_app = QuarkusApp(new_project(), props)
            stop_task.quarkus_app = quarkus_app

        try:
            if not test_task.system_properties.get("quarkus.http.test-port"):  # assuming this attribute exists
                for k, v in props.items():
                    if System.getProperty(k) is None:  # assuming this method exists
                        test_task.jvm_argument_providers.add(lambda: [f"-D{k}={v}"])
        except AttributeError as e:
            logging.error(f"Error setting system property {e}")

    @staticmethod
    def set_system_property(stop_task, key, value) -> None:
        if not System.get_properties().get(key):
            System.set_property(key, value)
            stop_task.restore_system_props[key] = System.getProperty(key)

    @staticmethod
    def new_project() -> Any:  # assuming this method exists in QuarkusApp class
        pass

class StopTask:
    application = None
    system_properties = {}
    restore_system_props = {}

class QuarkusAppExtension:
    def get_native_builder_image_property(self) -> str:
        return "native-builder-image"

    def get_system_properties(self) -> Dict[str, Any]:
        return {"system-property-1": "value-1", "system-property-2": "value-2"}

class QuarkusApp:
    @staticmethod
    def new_application(project: Any, props: Dict[str, str]) -> Any:  # assuming this method exists in QuarkusApp class
        pass

if __name__ == "__main__":
    StartTask.quarkus_start("stop_task")
```

Please note that the above Python code is a direct translation of the Java code and may not be optimal or idiomatic for Python.