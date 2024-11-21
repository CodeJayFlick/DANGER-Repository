class NoSymbolApplier:
    def __init__(self, applicator, iter):
        self.symbol = next(iter)

    def apply_to(self, apply_to_applier):
        # Do nothing.
        pass

    def apply(self):
        # Do nothing.
        pass


# Example usage:
applicator = "PdbApplicator"  # Replace with actual PdbApplicator instance
iter = iter(["Symbol1", "Symbol2"])  # Replace with actual AbstractMsSymbolIterator instance

no_symbol_applier = NoSymbolApplier(applicator, iter)
