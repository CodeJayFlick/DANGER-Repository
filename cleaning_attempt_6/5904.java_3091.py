class CustomLoadingAddressTableModel:
    def __init__(self, model_name: str, service_provider, program, loader, monitor):
        self.loader = loader
        super().__init__(model_name, service_provider, program, monitor)

    def __init__(self, model_name: str, service_provider, program, loader, monitor, load_incrementally=False):
        self.loader = loader
        super().__init__(model_name, service_provider, program, monitor, load_incrementally)

    def do_load(self, accumulator, monitor) -> None:
        try:
            self.loader.load(accumulator, monitor)
        except Exception as e:
            print(f"An error occurred: {e}")
