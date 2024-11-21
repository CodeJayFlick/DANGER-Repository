Here is the translation of the Java interface `BundleHostListener` into a Python class:

```python
class BundleHostListener:
    def bundle_built(self, bundle: 'GhidraBundle', summary: str) -> None:
        pass  # do nothing for now

    def bundle_enablement_change(self, bundle: 'GhidraBundle', new_enablement: bool) -> None:
        pass  # do nothing for now

    def bundle_activation_change(self, bundle: 'GhidraBundle', new_activation: bool) -> None:
        pass  # do nothing for now

    def bundle_added(self, bundle: 'GhidraBundle') -> None:
        pass  # do nothing for now

    def bundles_added(self, bundles: list['GhidraBundle']) -> None:
        for bundle in bundles:
            self.bundle_added(bundle)

    def bundle_removed(self, bundle: 'GhidraBundle') -> None:
        pass  # do nothing for now

    def bundles_removed(self, bundles: list['GhidraBundle']) -> None:
        for bundle in bundles:
            self.bundle_removed(bundle)

    def bundle_exception(self, exception: 'GhidraBundleException') -> None:
        pass  # do nothing for now
```

Note that I used the `-> None` syntax to indicate that these methods return no value. In Python, this is equivalent to returning `None`.