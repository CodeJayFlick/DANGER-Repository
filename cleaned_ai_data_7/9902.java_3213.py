import threading

class DefaultGTreeDataTransformer:
    def __init__(self):
        self.localized_results = threading.local()

    def transform(self, node):
        results = getattr(self.localized_results, 'results', None)
        if not results:
            results = []
            setattr(self.localized_results, 'results', results)

        results.clear()
        results.append(node.display_text())
        return results
