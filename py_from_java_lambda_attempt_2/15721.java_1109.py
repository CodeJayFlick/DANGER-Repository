Here is the translation of the Java code into Python:

```Python
import logging
from typing import List, Optional

class Trainer:
    def __init__(self, model: 'Model', training_config):
        self.model = model
        self.manager = manager = model.get_nd_manager().new_sub_manager()
        manager.set_name("trainer")
        self.devices = devices = training_config.get_devices()
        self.loss = loss = training_config.get_loss_function()
        if not loss:
            raise ValueError("You must specify a loss for the trainer")
        self.evaluators = evaluators = []
        evaluators.append(loss)  # track loss as an evaluator by default
        self.executor_service = executor_service = training_config.get_executor_service()

        parameter_server = manager.get_engine().new_parameter_server(training_config.get_optimizer())
        self.parameter_store = ParameterStore(manager, False)
        self.parameter_store.set_parameter_server(parameter_server, devices)

        self.listeners = listeners = training_config.get_training_listeners()
        for listener in listeners:
            listener.on_training_begin(self)

    def initialize(self, *shapes):
        self.model.block.initialize(self.manager, self.model.data_type(), shapes)
        # call get_value on all params to initialize on all devices
        for param in self.model.block.parameters():
            for device in self.devices:
                self.parameter_store.get_value(param.value, device, True)

    def iterate_dataset(self, dataset):
        return dataset.get_data(self.manager, self.executor_service)

    def new_gradient_collector(self):
        return self.manager.get_engine().new_gradient_collector()

    def forward(self, input: 'NDList'):
        begin = logging.nanoTime()
        try:
            output = self.model.block.forward(self.parameter_store, input, True)
        finally:
            self.add_metric("forward", begin)

        return output

    def evaluate(self, input: 'NDList'):
        return self.model.block.forward(self.parameter_store, input, False, None)

    def step(self):
        if not self.gradients_checked:
            self.check_gradients()

        begin = logging.nanoTime()
        self.parameter_store.update_all_parameters()
        self.add_metric("step", begin)

    @property
    def metrics(self) -> 'Metrics':
        return self._metrics

    @metrics.setter
    def metrics(self, value):
        self._metrics = value

    @property
    def devices(self) -> List['Device']:
        return self._devices

    @property
    def loss(self) -> 'Loss':
        return self._loss

    @property
    def model(self) -> 'Model':
        return self._model

    @property
    def executor_service(self) -> Optional['ExecutorService']:
        return self.executor_service

    @property
    def evaluators(self) -> List['Evaluator']:
        return self.evaluators

    def notify_listeners(self, listener_consumer):
        for listener in self.listeners:
            listener_consumer(listener)

    def get_training_result(self):
        result = TrainingResult()
        for listener in self.listeners:
            if isinstance(listener, EpochTrainingListener):
                result.epoch = listener.num_epochs
            elif isinstance(listener, EvaluatorTrainingListener):
                l = (EvaluatorTrainingListener) listener
                result.evaluations = l.latest_evaluations

        return result

    def get_manager(self):
        return self.manager

    def close(self):
        for listener in self.listeners:
            listener.on_training_end(self)

        self.parameter_store.sync()
        self.manager.close()

    def check_gradients(self):
        grads = []
        for param in self.model.block.parameters():
            if param.requires_gradient:
                grads.append(self.parameter_store.get_value(param.value, self.devices[0], True).get_gradient())

        try:
            scoped = self.manager.new_sub_manager()
            scoped.temp_attach_all(NDList(grads))
            list_ = NDList([sum(x) for x in zip(*grads)])
            grad_sum = sum(list_)
            if grad_sum == 0.0:
                raise ValueError("Gradient values are all zeros, please call gradient_collector.backward() on your target NDArray (usually loss), before calling step()")
        finally:
            self.gradients_checked = True

    def add_metric(self, metric_name: str, begin):
        if self.metrics and begin > 0.0:
            self.metrics.add_metric(metric_name, logging.nanoTime() - begin)
```

Please note that this is a direct translation of the Java code into Python, without considering any potential improvements or optimizations specific to the Python language.