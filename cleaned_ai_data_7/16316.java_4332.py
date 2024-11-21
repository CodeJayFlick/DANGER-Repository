class MLP:
    def __init__(self, input_dim, output_dim, hidden_dims):
        self.model = torch.nn.Sequential(
            torch.nn.Flatten(),
            *[
                torch.nn.Linear(input_dim if i == 0 else hidden_dims[i-1], hidden_dims[i])
                for i in range(len(hidden_dims))
            ],
            torch.nn.ReLU(),
            torch.nn.Linear(hidden_dims[-1], output_dim)
        )

    def __call__(self, x):
        return self.model(x)

# Example usage:
mlp = MLP(784, 10, [256, 128])
input_data = torch.randn(1, 784)  # Assuming input dimension is 784
output = mlp(input_data)
