Here is a translation of the Java code into equivalent Python code:

```Python
import gradle.api as api

class QuarkusAppPlugin:
    START_TASK_NAME = "nessie-quarkus-start"
    STOP_TASK_NAME = "nessie-quarkus-stop"
    EXTENSION_NAME = "nessieQuarkusApp"

    APP_CONFIG_NAME = "nessieQuarkusServer"
    RUNTIME_CONFIG_NAME = "nessieQuarkusRuntime"
    LAUNCH_CONFIG_NAME = "nessieQuarkusLaunch"

    def apply(self, target):
        extension = api.Extensions().create(EXTENSION_NAME, QuarkusAppExtension(), target)

        app_config = api.Configurations().create(APP_CONFIG_NAME)
        runtime_config = api.Configurations().create(RUNTIME_CONFIG_NAME)
        launch_config = api.Configurations().create(LAUNCH_CONFIG_NAME).extendsFrom(runtime_config, app_config)

        for task in target.get_tasks():
            if isinstance(task, Test):
                task.depends_on(START_TASK_NAME)
                task.finalized_by(STOP_TASK_NAME)

                inputs = task.inputs
                inputs.property("nessie.quarkus.props", extension.get_props_property())
                inputs.property("quarkus.native.builderImage", extension.get_native_builder_image_property())

                inputs.files(launch_config)

                def start_task():
                    start_task = target.get_tasks().get(START_TASK_NAME)
                    start_task.quarkus_start(task)

                task.do_first(start_task)

        target.get_tasks().register(START_TASK_NAME, StartTask())
        target.get_tasks().register(STOP_TASK_NAME, StopTask())

class QuarkusAppExtension:
    def get_props_property(self):
        # implement this method
        pass

    def get_native_builder_image_property(self):
        # implement this method
        pass


# This is not a part of the original code but I assume you want to define these classes as well.
class StartTask(api.Task):
    def quarkus_start(self, task):
        # implement this method
        pass

class StopTask(api.Task):
    def stop_quarkus(self, task):
        # implement this method
        pass


# This is not a part of the original code but I assume you want to define these classes as well.
class Test(api.Test):
    pass
```

Please note that Python does not have direct equivalents for Java's Gradle API. The above translation assumes that equivalent APIs are available in your Python environment, and it also makes some simplifications based on how the original code is structured.