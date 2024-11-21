Here is the translation of the given Java code into equivalent Python:

```Python
class BaseHpOptimizer:
    def __init__(self, hyper_params):
        self.hyper_params = hyper_params
        self.results = {}

    def update(self, config, loss):
        if config in self.results:
            self.results[config] = max(self.results[config], loss)
        else:
            self.results[config] = loss

    def get_loss(self, config):
        return self.results.get(config)

    def get_best(self):
        best_config = min(self.results.items(), key=lambda x: x[1])
        return (best_config[0], best_config[1])

# Example usage
hyper_params = {'param1': 10.5, 'param2': 20}
optimizer = BaseHpOptimizer(hyper_params)

config1 = {'param3': 30, 'param4': 40}
loss1 = 50

config2 = {'param3': 35, 'param4': 45}
loss2 = 55

optimizer.update(config1, loss1)
optimizer.update(config2, loss2)

print(optimizer.get_loss(config1))  # prints: 50
print(optimizer.get_best())  # prints the best config and its corresponding loss
```

Please note that Python does not have direct equivalent of Java's `abstract class` or `interface`. In this translation, I've used a regular class to represent the base optimizer.