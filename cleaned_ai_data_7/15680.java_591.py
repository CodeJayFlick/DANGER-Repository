import logging
from typing import List
import os
import subprocess
import io
import sys

class MemoryTrainingListener:
    def __init__(self):
        self.output_dir = None

    def set_output_dir(self, output_dir: str) -> None:
        self.output_dir = output_dir

    def on_training_batch(self, trainer, batch_data) -> None:
        metrics = trainer.get_metrics()
        self.collect_memory_info(metrics)

    def on_validation_batch(self, trainer, batch_data) -> None:
        metrics = trainer.get_metrics()
        self.collect_memory_info(metrics)

    def on_training_end(self, trainer) -> None:
        if not hasattr(trainer, 'get_metrics'):
            return
        metrics = trainer.get_metrics()
        self.dump_memory_info(metrics, self.output_dir)

    @staticmethod
    def collect_memory_info(metrics: dict) -> None:
        try:
            mem_usage = management.Management().get_heap_memory_usage()
            non_heap_used = management.Management().get_non_heap_memory_usage()

            heap_used = mem_usage.get_used()
            non_heap_used = non_heap_used.get_used()

            metrics['Heap'] = {'value': heap_used, 'unit': 'bytes'}
            metrics['Non-heap'] = {'value': non_heap_used, 'unit': 'bytes'}

            gpu_count = CudaUtils().get_gpu_count()
            for i in range(gpu_count):
                device = Device.gpu(i)
                mem_usage = CudaUtils().get_gpu_memory(device)

                metrics[f'GPU-{i}'] = {'value': mem_usage.get_committed(), 'unit': 'bytes'}
        except Exception as e:
            logging.error(f"Failed to collect memory info: {e}")

    @staticmethod
    def dump_memory_info(metrics, log_dir) -> None:
        if not hasattr(metrics, 'keys') or not metrics or not log_dir:
            return

        try:
            os.makedirs(log_dir, exist_ok=True)
            file_path = os.path.join(log_dir, "memory.log")
            with open(file_path, 'a', encoding='utf-8') as f:
                for metric_name in metrics.keys():
                    if isinstance(metrics[metric_name], dict):
                        value = metrics[metric_name]['value']
                        unit = metrics[metric_name].get('unit')
                        print(f"{metric_name}: {value} {unit}", file=f)
        except Exception as e:
            logging.error(f"Failed to dump memory log: {e}")

    @staticmethod
    def get_process_info(metrics) -> None:
        if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
            try:
                pid = os.getpid()
                cmd = f'ps -o %cpu= -o rss= -p {pid}'
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                output = io.TextIOWrapper(process.stdout).read().strip()

                if not output:
                    return

                tokens = output.split()
                cpu_usage = float(tokens[0])
                rss_size = int(tokens[1]) * 1024
                metrics['cpu'] = {'value': cpu_usage, 'unit': '%'}
                metrics['rss'] = {'value': rss_size, 'unit': 'bytes'}

            except Exception as e:
                logging.error(f"Failed to execute cmd: {cmd}, error: {e}")
