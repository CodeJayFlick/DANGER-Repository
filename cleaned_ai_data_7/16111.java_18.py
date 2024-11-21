import tensorflow as tf

class TfLiteSymbolBlock:
    def __init__(self, interpreter: tf.lite.Interpreter, manager):
        self.interpreter = interpreter
        self.manager = manager

    def forward(self, parameter_store, inputs, training=False, params=None):
        input_arrays = [input.to_numpy() for input in inputs]
        self.interpreter.run(input_arrays)

        output_tensors = []
        for i in range(self.interpreter.get_output_tensor_count()):
            output_tensors.append(tf.convert_to_tensor(self.interpreter.get_output_tensor(i)))

        result = tf.stack(output_tensors)
        return result

    def close(self):
        self.interpreter.close()
