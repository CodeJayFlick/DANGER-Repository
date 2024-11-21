Here is a translation of the Java code into equivalent Python:

```Python
import os
from typing import Dict, Any

class QuarkusApp:
    def __init__(self):
        pass

    @staticmethod
    def new_application(project: str, repo_system: str, repo_session: str, app_artifact_id: str) -> 'QuarkusApp':
        try:
            # Resolve the application model
            resolver = MavenArtifactResolver(repo_system, repo_session)
            app_model = BootstrapAppModelResolver(resolver).resolve_model(app_artifact_id)

            return QuarkusApp.new_application(app_model, project, os.path.join(os.getcwd(), 'target'), {})

        except Exception as e:
            raise MojoExecutionException(f"Failed to resolve application model {app_artifact_id} dependencies", e)

    @staticmethod
    def new_application(app_model: str, project_root: str, target_directory: str, application_properties: Dict[str, Any]) -> 'QuarkusApp':
        try:
            # Create the Quarkus bootstrap instance
            bootstrap = QuarkusBootstrap()
            app_artifact = AppArtifactCoords.from_string(app_artifact_id)
            base_class_loader = classloader

            return new_application(bootstrap, project_root, target_directory, application_properties)

        except Exception as e:
            raise MojoExecutionException(f"Failure starting Nessie Daemon", e)

    @staticmethod
    def configure_moj_config_source(startup_action: str, application_properties: Dict[str, Any]) -> None:
        if not application_properties:
            return

        try:
            # Load the mojo config source class
            mojo_config_source_class = load_class(MOJO_CONFIG_SOURCE_CLASSNAME)

            method = mojo_config_source_class.get_method("setProperties", [Properties])
            method.invoke(None, application_properties)

        except Exception as e:
            raise ReflectiveOperationException(f"Failed to configure moj config source: {e}")

    @staticmethod
    def exit_handler(startup_action: str) -> None:
        try:
            # Load the application lifecycle manager class
            app_lifecycle_manager_class = load_class("io.quarkus.runtime.ApplicationLifecycleManager")

            method = app_lifecycle_manager_class.get_method("setDefaultExitCodeHandler", [BiConsumer])
            method.invoke(None, lambda i, t: {})

        except Exception as e:
            raise ReflectiveOperationException(f"Failed to configure exit handler: {e}")

    @staticmethod
    def find_mojo_config_source_dependency() -> Any:
        try:
            # Load the mojo config source class
            mojo_config_source_class = load_class(MOJO_CONFIG_SOURCE_CLASSNAME)

            return AdditionalDependency(mojo_config_source_class.get_location(), False, False)

        except Exception as e:
            raise MojoExecutionException(f"Failed to find moj config source dependency: {e}")

    def close(self) -> None:
        self.running_app.close()

class MojoExecutionException(Exception):
    pass

def load_class(class_name: str) -> Any:
    try:
        return globals()[class_name]

    except Exception as e:
        raise ReflectiveOperationException(f"Failed to load class {class_name}: {e}")

if __name__ == "__main__":
    QuarkusApp.new_application("org. projectnessie.quarkus.maven", "path/to/project/root", os.path.join(os.getcwd(), 'target'), {})
```

Please note that Python does not support direct translation of Java code into equivalent Python, as the two languages have different syntax and semantics. The above code is a manual translation based on my understanding of the provided Java code.

The `MojoExecutionException` class in this example is an exception class used to handle exceptions during execution.