import logging

# Define constants for the GNU General Public License
GPL_VERSION = "3"
GNU_LICENSE_URL = "http://www.gnu.org/licenses/"

class LastResourcePackResponse:
    def __init__(self):
        self.name = "Last Resource Pack Response"
        self.description = "Returns the last resource pack response received from a player."
        self.examples = ["if player's last resource pack response is deny or download fail:"]
        self.since = "2.4"
        self.required_plugins = ["Paper 1.9 or newer"]

    def convert(self, p):
        return p.get_resource_pack_status()

    @property
    def property_name(self):
        return "resource pack response"

    @property
    def return_type(self):
        from enum import Enum
        class Status(Enum):
            pass

        return Status


# Register the expression with Skript
def register_expression():
    if hasattr(Player, 'get_resource_pack_status'):
        logging.info("Registering Last Resource Pack Response")
        # Add code to register the expression here
