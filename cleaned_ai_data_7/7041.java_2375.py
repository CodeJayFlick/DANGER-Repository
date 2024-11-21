# This is a comment block in Python, similar to Java's multiline comments.
"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

class ImageRootMarshmallow:
    """
    @see https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/image.h
    """

    RESOLUTION_METHOD = 0
    IMT_CONFLICT_METHOD = 1
    DEFAULT_IMT = 2
    CALLEE_SAVE_METHOD = 3
    REFS_ONLY_SAVE_METHOD = 4
    REFS_AND_ARGS_SAVE_METHOD = 5
    DEX_CACHES = 6
    CLASS_ROOTS = 7
    IMAGE_ROOTS_MAX = 8

# This is equivalent to the Java enum. Python does not have a built-in enum type, but we can use class constants.
