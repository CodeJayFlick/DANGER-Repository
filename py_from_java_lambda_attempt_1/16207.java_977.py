Here is the translation of the given Java code into equivalent Python:

```Python
import os
import sys
from datetime import datetime
import logging
import copy

class Benchmark:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    @staticmethod
    def main(args):
        arch = os.environ.get("os.arch")
        if not (arch == "x86_64" or arch == "amd64"):
            print(f"{arch} is not supported.")
            return

        args_list = copy.deepcopy(list(map(str, args)))
        success = False
        if len(args) > 0 and args[0] == "-ndlist-gen":
            success = NDListGenerator.generate(copy.deepcopy(args[1:]))
        else:
            multithreading = any(arg in ("-t", "--threads") for arg in args)
            config_engines(multithreading)

            if multithreading:
                success = MultithreadedBenchmark().run_benchmark(args)
            else:
                success = Benchmark().run_benchmark(args)

        if not success:
            sys.exit(-1)  # NOPMD

    def predict(self, arguments, metrics, iteration):
        device = Engine.get_engine(arguments["engine"]).default_device()
        try:
            model = load_model(arguments, metrics, device)
            predictor = model.new_predictor()

            predictor.predict(None)  # warmup
            predictor.set_metrics(metrics)

            for i in range(iteration):
                result = predictor.predict(None)
                self.logger.info(f"Predicted {i+1}th iteration.")
        except (IOException, ModelException, TranslateException as e:
            print(e)

    @staticmethod
    def config_engines(multithreading):
        if multithreading:
            os.environ["ai.djl.pytorch.num_interop_threads"] = "1"
            os.environ["ai.djl.pytorch.num_threads"] = "1"

        os.environ["ai.djl.tflite.disable_alternative"] = "true"
        os.environ["ai.djl.dlr.disable_alternative"] = "true"
        os.environ["ai.djl.paddlepaddle.disable_alternative"] = "true"
        os.environ["ai.djl.onnx.disable_alternative"] = "true"
        os.environ["ai.djl.tensorrt.disable_alternative"] = "true"


class MultithreadedBenchmark:
    def run_benchmark(self, args):
        # Implementation of multithreading benchmark
        pass


def load_model(arguments, metrics, device):
    # Load model implementation
    pass

if __name__ == "__main__":
    Benchmark.main(sys.argv[1:])
```

Note that this is a direct translation from Java to Python and may not be the most idiomatic or efficient way of writing in Python.