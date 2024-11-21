# Licensed under Apache License 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

import os.path as path_utils

class AbstractModelForGdbInferiorLauncherTest:
    INF1_PATH = [path_utils.join('Inferiors', '1')]

    def get_expected_launcher_path(self):
        return self.INF1_PATH

    def find_launcher(self) -> dict:
        launcher = {'m': None, 'find': lambda x: {TargetLauncher.__name__: x}}
        return launcher.get(TargetLauncher.__name__, {}).get('class', {})

# Note that Python does not have direct equivalent of Java's "throws Throwable" syntax.
