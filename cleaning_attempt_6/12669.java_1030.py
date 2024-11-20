import importlib.util

def get_relocation_handlers():
    relocation_handler_module = 'relocation_handler'
    try:
        module_spec = importlib.util.spec_from_file_location(relocation_handler_module)
        relocation_handler_class = getattr(module_spec.module, 'RelocationHandler')
        return [cls() for cls in classfinder.find_classes(relocation_handler_class)]
    except ImportError as e:
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    print(get_relocation_handlers())
