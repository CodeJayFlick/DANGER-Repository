Here is the translation of the given Java code into equivalent Python:

```Python
import numpy as np
from typing import List

class LSTMBlock:
    def __init__(self):
        self.gates = 4

    def forward(self, inputs: List[np.ndarray], training: bool) -> List[np.ndarray]:
        input_array = inputs[0]
        device = 'cpu' if not hasattr(input_array, 'device') else str(input_array.device)
        
        rnn_params = []
        for param in self.parameters.values():
            # Assuming you have a function to get the value of parameter from store
            rnn_param_value = get_parameter_store().get(param, device, training)
            rnn_params.append(rnn_param_value)

        if len(inputs) == 1:
            batch_index = 0 if not hasattr(input_array, 'batch_first') else 1
            state_shape = (self.num_layers * self.num_directions,) + input_array.shape[batch_index:]
            
            # hidden state
            inputs.append(np.zeros(state_shape))
            # cell
            inputs.append(np.zeros(state_shape))

        outputs = np.lstm(input_array, 
                          [inputs[1], inputs[2]], 
                          rnn_params, 
                          self.has_biases, 
                          self.num_layers, 
                          self.drop_rate, 
                          training, 
                          self.bidirectional, 
                          batch_index)

        if self.return_state:
            return outputs
        else:
            for output in outputs[1:]:
                np.close(output)
            return [outputs[0]]

    @classmethod
    def builder(cls):
        return cls()

class Builder:
    def __init__(self):
        pass

    def build(self) -> 'LSTMBlock':
        if self.state_size <= 0 or self.num_layers <= 0:
            raise ValueError("Must set stateSize and numStackedLayers")
        
        return LSTMBlock()
```

Please note that Python does not have direct equivalent of Java's `PairList` so I replaced it with a list. Also, the code assumes you have functions to get the value of parameter from store (`get_parameter_store`) and close an array (`np.close`).