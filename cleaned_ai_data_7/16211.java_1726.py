import argparse
import unittest
from typing import Dict, List

class BenchmarkTest(unittest.TestCase):

    def test_help(self):
        args = ["-h"]
        Benchmark.main(args)

    def test_arguments(self):
        options = {"p": "/opt/ml/resnet18_v1", "s": "(1)s,(1)d,(1)u,(1)b,(1)i,(1)l,(1)B,(1)", 
                   "model_options": "fp16,dlaCore=1", "model_arguments": "width=28"}
        parser = argparse.ArgumentParser()
        for key, value in options.items():
            if "," not in value:
                parser.add_argument(f"-{key}", type=str)
            else:
                parser.add_argument(f"--{key}", type=str)

        args = ["-p", "/opt/ml/resnet18_v1", "-s", "(1)s,(1)d,(1)u,(1)b,(1)i,(1)l,(1)B,(1)", 
               "--model-options", "fp16,dlaCore=1", "--model-arguments", "width=28"]
        try:
            parsed_args = parser.parse_args(args)
            self.assertEqual(parsed_args.p, "/opt/ml/resnet18_v1")
            self.assertEqual(parsed_args.s, "(1)s,(1)d,(1)u,(1)b,(1)i,(1)l,(1)B,(1)")
            model_options: Dict[str, str] = {}
            for key in parsed_args.model_options.split(","):
                if "=" not in key:
                    raise ValueError(f"Invalid option {key}")
                k, v = key.strip().split("=")
                model_options[k] = v
            self.assertEqual(model_options["dlaCore"], "1")
            self.assertTrue("fp16" in model_options)

        except Exception as e:
            with self.assertRaises(type(e)):
                parser.parse_args(["-p", "/opt/ml/resnet18_v1", "-s", "(1)S"])

    def test_benchmark(self):
        args = ["-u", "djl://ai.djl.mxnet/resnet/0.0.1/resnet18_v1", 
               "-s", "1,3,224,224", "-c", "2"]
        Benchmark().runBenchmark(args)

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertIs'), "This test requires Python 3.5 or later")
    def test_multithreaded_benchmark(self):
        import os
        try:
            args = ["-e", "MXNet", 
                   "-u", "djl://ai.djl.mxnet/resnet/0.0.1/resnet18_v1",
                   "-s", "(1,3,224,224)f", 
                   "-d", "1", 
                   "-l", "1", 
                   "-c", "2", 
                   "-t", "-1", 
                   "-g", "-1"]
            Benchmark.main(args)
        finally:
            if 'collect_memory' in os.environ:
                del os.environ['collect_memory']

if __name__ == '__main__':
    unittest.main()
