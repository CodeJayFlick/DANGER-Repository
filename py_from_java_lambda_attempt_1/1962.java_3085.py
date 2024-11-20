Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Dict, Any

class GadpClientTargetLauncher:
    def launch(self, arguments: Dict[str, Any]) -> None:
        self.delegate.assert_valid()
        return self.model.send_checked(
            Gadp.LaunchRequest.newBuilder().set_path(GadpValueUtils.make_path(self.path)).add_all_argument(
                GadpValueUtils.make_arguments(arguments)),
            Gadp.LaunchReply.getDefaultInstance()).then_apply(lambda x: None)

    def get_parameters(self) -> Dict[str, Any]:
        return TargetMethod.get_parameters(self)
```

Please note that Python does not have direct equivalent of Java's `CompletableFuture` and some other features. Also, the above code assumes you are using a library like google.protobuf to work with protobuf messages (like Gadp.LaunchRequest).