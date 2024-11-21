Here is a translation of the Java code into equivalent Python code:

```Python
import logging
from urllib.parse import urlparse
from packaging import version

class QuarkusAppStartMojo:
    def __init__(self):
        self.repo_system = None
        self.repo_session = None
        self.plugin_descriptor = None
        self.app_artifact_id = None
        self.application_properties = {}
        self.system_properties = {}
        self.output_properties = {}

    @staticmethod
    def to_url(artifact):
        try:
            return urlparse(str(artifact.get_file())).geturl()
        except Exception as e:
            raise ValueError(f"Failed to create URL from artifact: {e}")

    def execute(self, project=None, repo_system=None, repo_session=None, app_artifact_id=None,
                application_properties=None, system_properties=None):
        if self.is_skipped():
            logging.debug("Execution is skipped")
            return

        if system_properties:
            for key, value in system_properties.items():
                System.set_property(key, value)

        try:
            app_coords = AppArtifactCoords.from_string(app_artifact_id)
        except Exception as e:
            raise MojoExecutionException(f"Failed to parse artifact coordinates: {e}")

        # Check that the artifact is present
        if not self.plugin_descriptor.get_artifacts().get(app_coords):
            raise MojoExecutionException(
                f"Artifact {app_coords} not found in plugin dependencies")

        logging.info("Starting Quarkus application.")

        try:
            urls = [self.to_url(artifact) for artifact in self.plugin_descriptor.get_artifacts()]
            mirror_cl = URLClassLoader(urls, MavenProject.__loader__)
        except Exception as e:
            raise MojoExecutionException(f"Failed to create class loader: {e}")

        if reset_java_util_logging():
            old_log_manager = System.getProperty("java.util.logging.manager")
            try:
                logging.config.reset()
            finally:
                if old_log_manager is None:
                    System.getProperties().remove("java.util.logging.manager")
                else:
                    System.setProperty("java.util.logging.manager", old_log_manager)
                logging.config.reset()

        quarkus_app = self.new_application(project, repo_system, repo_session,
                                            app_artifact_id, application_properties)

        if output_properties:
            project_properties = project.get_properties()
            for key, value in output_properties.items():
                try:
                    project_properties.set_property(key, str(value))
                except Exception as e:
                    raise MojoExecutionException(f"Failed to set property: {e}")

        logging.info("Quarkus application started.")

    def new_application(self, project=None, repo_system=None, repo_session=None,
                        app_artifact_id=None, application_properties=None):
        try:
            clazz = mirror_cl.load_class(QuarkusApp.__name__)
            method = getattr(clazz, "newApplication")
            return method(project, repo_system, repo_session, app_artifact_id,
                          application_properties)
        except Exception as e:
            raise MojoExecutionException(f"Failed to create quarkus application: {e}")

    def set_application_handle(self):
        try:
            self.quarkus_app.close()
        finally:
            mirror_cl.close()

            if reset_java_util_logging():
                old_log_manager = System.getProperty("java.util.logging.manager")
                if old_log_manager is None:
                    System.getProperties().remove("java.util.logging.manager")
                else:
                    System.setProperty("java.util.logging.manager", old_log_manager)
                logging.config.reset()
```

Note that this translation assumes a Python 3.7+ environment, and uses the `packaging` library for parsing version strings (which is not available in earlier versions of Python).