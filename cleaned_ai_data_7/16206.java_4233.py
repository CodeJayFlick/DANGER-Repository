import argparse
from typing import List, Tuple, Dict

class Arguments:
    def __init__(self):
        self.model_url = None
        self.model_name = None
        self.engine = "default"
        self.model_options = ""
        self.model_arguments = ""
        self.output_dir = "build"
        self.duration = 0
        self.iteration = 1
        self.threads = 0
        self.max_gpus = float('inf')
        self.delay = 0
        self.input_shapes = []

    def parse_args(self, args):
        parser = argparse.ArgumentParser(description='Benchmark arguments.')
        parser.add_argument('--model-path', help='Model directory file path.')
        parser.add_argument('--model-url', help='Model archive file URL.')
        parser.add_argument('--engine', default="default", help='Choose an Engine for the benchmark.')
        parser.add_argument('--input-shapes', required=True, help='Input data shapes for the model.')
        parser.add_argument('-d', '--duration', type=int, help='Duration of the test in minutes.')
        parser.add_argument('-c', '--iteration', type=int, help='Number of total iterations.')
        parser.add_argument('-t', '--threads', type=int, help='Number of inference threads.')
        parser.add_argument('-g', '--max-gpus', type=int, default=float('inf'), help='Number of GPUS to run multithreading inference.')
        parser.add_argument('-l', '--delay', type=int, help='Delay of incremental threads.')
        parser.add_argument('--output-dir', default="build", help='Directory for output logs.')

        self.args = parser.parse_args(args)

    def get_duration(self):
        return self.duration

    def get_engine(self):
        return self.engine

    def get_model_url(self):
        return self.model_url

    def get_model_name(self):
        return self.model_name

    def get_model_options(self) -> Dict[str, str]:
        if not self.model_options:
            return {}
        options = {}
        for option in self.model_options.split(","):
            tokens = option.split("=", 2)
            if len(tokens) == 2:
                options[tokens[0].strip()] = tokens[1].strip()
            else:
                options[tokens[0].strip()] = ""
        return options

    def get_model_arguments(self) -> Dict[str, str]:
        if not self.model_arguments:
            return {}
        arguments = {}
        for option in self.model_arguments.split(","):
            tokens = option.split("=", 2)
            if len(tokens) == 2:
                arguments[tokens[0].strip()] = tokens[1].strip()
            else:
                arguments[tokens[0].strip()] = ""
        return arguments

    def get_iteration(self):
        return self.iteration

    def get_threads(self):
        return self.threads

    def get_max_gpus(self):
        return self.max_gpus

    def get_output_dir(self):
        if not self.output_dir:
            self.output_dir = "build"
        return self.output_dir

    def get_delay(self):
        return self.delay

    def get_input_shapes(self) -> List[Tuple[object, object]]:
        return self.input_shapes
