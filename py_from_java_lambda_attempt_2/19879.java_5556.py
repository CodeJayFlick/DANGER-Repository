Here is the translation of the Java code to Python:

```Python
import json
import os
from collections import defaultdict

class Environment:
    def __init__(self):
        pass

    def initialize(self, data_root, runner_root, dev_mode=False):
        # Implementation left out for brevity
        pass

    def run_tests(self, runner_root, tests_root, dev_mode=False, max_memory='1G'):
        # Implementation left out for brevity
        return TestResults()

class NonNullPair:
    def __init__(self, env, error):
        self.env = env
        self.error = error

class TestResults:
    def __init__(self):
        pass

    def get_succeeded(self):
        # Implementation left out for brevity
        return []

    def get_failed(self):
        # Implementation left out for brevity
        return defaultdict(list)

def main():
    import sys
    from collections import OrderedDict

    if len(sys.argv) != 5:
        print("Usage: python platform_main.py <runner_root> <tests_root> <data_root> <envs_root>")
        exit(1)

    runner_root = os.path.abspath(sys.argv[1])
    tests_root = os.path.abspath(sys.argv[2])
    data_root = os.path.abspath(sys.argv[3])
    envs_root = os.path.abspath(sys.argv[4])

    if not (os.path.exists(runner_root) and
            os.path.exists(tests_root) and
            os.path.exists(data_root) and
            os.path.exists(envs_root)):
        print("Invalid input")
        exit(1)

    dev_mode = sys.argv[5].lower() == 'true'

    envs = []
    if os.path.isdir(envs_root):
        for path in os.listdir(envs_root):
            try:
                with open(os.path.join(envs_root, path), 'r') as f:
                    env_json = json.load(f)
                    env = Environment()
                    env.__dict__.update(env_json)  # Assuming the JSON data is a dictionary
                    envs.append(env)
            except (FileNotFoundError, json.JSONDecodeError):
                pass

    else:
        try:
            with open(envs_root, 'r') as f:
                env_json = json.load(f)
                env = Environment()
                env.__dict__.update(env_json)  # Assuming the JSON data is a dictionary
                envs.append(env)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    print("Initializing Skript test platform...")
    for env in sorted([env.name for env in envs]):
        print(f"Starting testing on {env}...")

    all_tests = set()
    failures = defaultdict(list)

    for env in envs:
        if not os.path.exists(runner_root):
            break
        try:
            results = env.run_tests(runner_root, tests_root, dev_mode)
            succeeded = set(results.get_succeeded())
            failed = {k: v[0] for k, v in dict((f"test_{i}", f"{v}") for i, (k, v) in enumerate(failed.items())).items()}
        except Exception as e:
            print(f"Error occurred while running tests on {env.name}: {str(e)}")
            continue

    succeeded = sorted(list(all_tests - set(failed.keys())))
    failed_names = list(failed.keys())

    if not all_tests.issubset(set(succeeded)):
        for name in failed_names:
            errors = failures[name]
            print(f"Failed: {name} (on {len(errors)} environments)")
            for error, env_name in zip(errors, [env.name for env in envs]):
                print(f"  {error[1]} (on {env_name})")

    if len(failed_names) > 0:
        sys.exit(len(failed_names))

if __name__ == "__main__":
    main()
```

This Python code is a direct translation of the Java code. It assumes that `Environment`, `NonNullPair`, and `TestResults` are classes defined elsewhere in your program, with methods like `initialize`, `run_tests`, etc., as they were in the original Java code.