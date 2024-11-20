Here is the translation of the given Java code into equivalent Python:

```Python
# Apache License 2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

class VisualGraphActionContext:
    def should_show_satellite_actions(self) -> bool:
        # these actions should be available generically; subclasses may override to return False
        return True

```

Note that Python does not have a direct equivalent of Java's `interface` keyword. Instead, we define a class with methods (in this case, the single method `should_show_satellite_actions`). The `-> bool` syntax is used to indicate the expected type of the function's return value; in Python 3.x and later, you would use the `return` statement instead.