Here is the translation of the Java code to Python:
```python
import os
import collections

class DynamoTestResourceLifecycleManager:
    def __init__(self):
        self.dynamo = None

    def start(self) -> dict:
        if not self.dynamo:
            self.dynamo = LocalDynamoTestConnectionProviderSource()

        try:
            # Only start the Docker container (local Dynamo-compatible).
            # The DynamoDatabaseClient will be configured via Quarkus -> Quarkus-Dynamo / DynamoVersionStoreFactory.
            self.dynamo.start_dynamo()
        except Exception as e:
            raise RuntimeError(e)

        return {"quarkus.dynamodb.endpoint-override": self.dynamo.get_endpoint_uri()}

    def stop(self):
        if self.dynamo:
            try:
                # Stop the Docker container
                self.dynamo.stop()
            except Exception as e:
                raise RuntimeError(e)
            finally:
                self.dynamo = None

class LocalDynamoTestConnectionProviderSource:
    pass  # This class is not implemented in Java, so I left it empty in Python.
```
Note that I did not implement the `LocalDynamoTestConnectionProviderSource` class as it was not provided in the original code. You would need to implement this class or use an existing library to interact with DynamoDB.

Also, please note that Python does not have a direct equivalent of Java's `Map< String, String >`. I used a dictionary (`dict`) instead, which is similar but has some differences in usage and behavior.