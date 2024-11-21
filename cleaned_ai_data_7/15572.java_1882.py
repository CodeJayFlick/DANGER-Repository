class LambdaBlock:
    def __init__(self, lambda_func):
        self.lambda_func = lambda_func

    @staticmethod
    def singleton(lambda_func):
        return LambdaBlock(lambda x: [lambda_func(y) for y in x])

    def forward(self, inputs):
        return self.lambda_func(inputs)

    def get_output_shapes(self, input_shapes):
        output_list = []
        for shape in input_shapes:
            output_list.append(shape)
        return output_list

    def load_parameters(self, manager, is_):
        version = int.from_bytes(is_.read(1), 'big')
        if version == 2:
            self.read_input_shapes(is_)
        else:
            raise MalformedModelException("Unsupported encoding version: " + str(version))

    def __str__(self):
        return "Lambda()"
