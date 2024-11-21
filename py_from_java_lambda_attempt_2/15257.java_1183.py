Here is a translation of the Java code into equivalent Python code:

```Python
import hashlib
from typing import List, Optional

class PeerListAdapter:
    def __init__(self, context: object, on_click_listener: Optional[object] = None):
        self.inflater = LayoutInflater.from(context)
        self.card_elevation_selected = int(context.getResources().getDimensionPixelOffset(R.dimen.card_elevation_selected))
        self.on_click_listener = on_click_listener
        super().__init__()

    @staticmethod
    def build_list_items(context: object, peers: List[object], hostnames: dict) -> List:
        items = []
        for peer in peers:
            inet_address = peer.get_address().get_addr()
            ip = inet_address.getHostAddress()
            port = peer.get_port()
            display_host_and_port = HostAndPort(ip, port)
            hostname = hostnames.get(inet_address)
            if not hostname:
                hostname = ip
            height = peer.get_best_height()
            version_message = peer.get_peer_version_message()
            protocol = f"protocol: {version_message.client_version}"
            services = str(peer.to_string_services(version_message.local_services)).lower(locale.US)
            ping_time = peer.get_ping_time()
            if ping_time < long.MAX_VALUE:
                ping = context.getString(R.string.peer_list_row_ping_time, ping_time)
            else:
                ping = None
            icon = None
            if peer.is_download_data():
                icon = context.getDrawable(R.drawable.ic_sync_white_24dp)
                icon.setTint(context.getColor(R.color.fg_significant))
            items.append(ListItem(display_host_and_port, display_host_and_port, height, version_message.subVer, protocol, services, ping, icon))
        return items

    class ListItem:
        def __init__(self, host_and_port: object, display_host_and_port: object, height: int, version: str, protocol: str, services: str, ping: Optional[str], icon: Optional[object]):
            self.id = id(host_and_port)
            self.host_and_port = host_and_port
            self.display_host_and_port = display_host_and_port
            self.height = height
            self.version = version
            self.protocol = protocol
            self.services = services
            self.ping = ping
            self.icon = icon

        @staticmethod
        def id(host_and_port: object) -> int:
            return hashlib.farm_hash_fingerprint64().newHasher().putUnencodedChars(str(host_and_port.getHost())).putInt(int(host_and_port.getPort())).hash().asLong()

    class OnClickListener:
        def on_peer_click(self, view: object, peer_host_and_port: object):
            pass

    @staticmethod
    def position_of(peer_host_and_port: object) -> int:
        if not peer_host_and_port:
            return RecyclerView.NO_POSITION
        list = current_list()
        for i in range(len(list)):
            item = list[i]
            if item.host_and_port == peer_host_and_port:
                return i
        return RecyclerView.NO_POSITION

    def set_selected_peer(self, new_selected_peer: object):
        if self.selected_peer_host_and_port is not None and new_selected_peer != self.selected_peer_host_and_port:
            notify_item_changed(position_of(self.selected_peer_host_and_port), EnumSet.of(ChangeType.SELECTION))
        if new_selected_peer is not None:
            notify_item_changed(position_of(new_selected_peer), EnumSet.of(ChangeType.SELECTION))
        self.selected_peer_host_and_port = new_selected_peer

    def onBindViewHolder(holder: object, position: int):
        raise UnsupportedOperationException()

    def onBindViewHolder(holder: object, position: int, payloads: List[object]):
        full_bind = not payloads
        changes = EnumSet.none()
        for payload in payloads:
            changes.addAll(payload)
        item = self.get_item(position)
        if full_bind or changes.contains(ChangeType.SELECTION):
            selected = item.host_and_port == self.selected_peer_host_and_port
            holder.itemView.setSelected(selected)
            (holder.itemView).setCardElevation(selected and card_elevation_selected or 0)

    def getItemId(self, position: int) -> int:
        return super().getItemId(position)

class ViewHolder(RecyclerView.ViewHolder):
    def __init__(self, itemView: object):
        super().__init__(itemView)
        self.host_view = itemView.findViewById(R.id.peer_list_row_host)
        self.height_view = itemView.findViewById(R.id.peer_list_row_height)
        self.version_view = itemView.findViewById(R.id.peer_list_row_version)
        self.protocol_view = itemView.findViewById(R.id.peer_list_row_protocol)
        self.services_view = itemView.findViewById(R.id.peer_list_row_services)
        self.ping_view = itemView.findViewById(R.id.peer_list_row_ping)
        self.icon_view = itemView.findViewById(R.id.peer_list_row_icon)

class HostAndPort:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def equals(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return False
        return self.host == other.host and self.port == other.port

class ChangeType(Enum):
    HOST = 1
    PING = 2
    ICON = 3
    SELECTION = 4