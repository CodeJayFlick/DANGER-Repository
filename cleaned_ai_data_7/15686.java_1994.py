import torch.optim as optim
from torch import Device, Tensor

class LocalParameterServer:
    def __init__(self, optimizer):
        self.optimizer = optimizer

    def init(self, parameter_id: str, value: list) -> None:
        pass  # No implementation needed for this method in Python

    def update(self, parameter_id: str, grads: list, params: list) -> None:
        first_device = Device(params[0].device)
        
        # Reduce gradient from all devices to the first device
        aggregated_grad = Tensor(1.0).to(first_device)
        for i in range(1, len(grads)):
            grad_copy = grads[i].to(device=first_device, non_blocking=True)
            aggregated_grad.add_(grad_copy)

        # Update weights on different devices with reduced gradient
        for param in params:
            if param.device == first_device:
                self.optimizer.update(parameter_id, param, aggregated_grad)
            else:
                grad_sum_copy = aggregated_grad.to(device=param.device, non_blocking=True)
                self.optimizer.update(parameter_id, param, grad_sum_copy)

    def close(self) -> None:
        pass  # No implementation needed for this method in Python
