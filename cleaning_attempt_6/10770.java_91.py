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

