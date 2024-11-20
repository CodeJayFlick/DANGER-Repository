import logging
from ai_djl import CudaUtils
import platform
import psutil

logging.basicConfig(level=logging.INFO)

def test_cuda_utils():
    if not CudaUtils.has_cudnn:
        return
    
    # Possible to have CUDA and not have a GPU.
    gpu_count = CudaUtils.get_gpu_count()
    if gpu_count == 0:
        return

    cuda_version = CudaUtils.get_cudnn_version()
    sm_version = CudaUtils.get_compute_capability(0)
    
    memory_usage = psutil.virtual_memory().percent
    logging.info("CUDA runtime version: {}, SM: {}".format(cuda_version, sm_version))
    logging.info("Memory usage: {}%".format(memory_usage))

    assert cuda_version >= 9020, "cuda 9.2+ required."

    supported_sm = ["37", "52", "60", "61", "70", "75"]
    if not any(sm == sm_version for sm in supported_sm):
        raise ValueError("Unsupported CUDA SM: {}".format(sm_version))

if __name__ == "__main__":
    test_cuda_utils()
