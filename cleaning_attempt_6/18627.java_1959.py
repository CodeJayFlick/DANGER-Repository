import json

class EchoSpringAppConfig:
    def __init__(self):
        self.object_mapper = None
        self.lambda_context = None
        self.local_validator_factory = None

    @property
    def object_mapper(self):
        if not self.object_mapper:
            self.object_mapper = json.JSONEncoder()
        return self.object_mapper

    @property
    def lambda_context(self):
        if not self.lambda_context:
            from your_module import MockLambdaContext  # replace 'your_module' with the actual module name
            self.lambda_context = MockLambdaContext()
        return self.lambda_context

    @property
    def local_validator_factory(self):
        if not self.local_validator_factory:
            from your_module import LocalValidatorFactory  # replace 'your_module' with the actual module name
            self.local_validator_factory = LocalValidatorFactory()
        return self.local_validator_factory
