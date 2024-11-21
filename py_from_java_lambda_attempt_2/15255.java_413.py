Here is a translation of the Java code into equivalent Python code:

```Python
# Copyright Andreas Schildbach or authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import os

class NetworkMonitorActivity:
    POSITION_PEER_LIST = 0
    POSITION_BLOCK_LIST = 1
    TAB_LABELS = [os.environ['R_string_network_monitor_peer_list_title'], 
                  os.environ['R_string_network_monitor_block_list_title']]

    def __init__(self):
        pass

    def on_create(self, savedInstanceState):
        super().on_create(savedInstanceState)

        self.set_content_view('network_monitor_content')
        pager = ViewPager2()
        pager_tabs = ViewPagerTabs()

        pager_tabs.add_tab_labels(TAB_LABELS)
        
        two_panes = os.environ['R_bool_network_monitor_two_panes']
        if two_panes:
            recyclerView = RecyclerView(pager.get_child_at(0))
            recyclerView.set_clip_to_padding(False)
            recyclerView.view_tree_observer().add_global_layout_listener(
                lambda: self.on_global_layout(recyclerView, pager)
            )
            pager.set_user_input_enabled(False)
            pager_tabs.set_mode(ViewPagerTabs.Mode.STATIC)
        else:
            pager.set_page_transformer(ZoomOutPageTransformer())
            pager.register_on_page_change_callback(pager_tabs.get_page_change_callback())
            pager_tabs.set_mode(ViewPagerTabs.Mode.DYNAMIC)

        pager.set_offscreen_page_limit(1)
        pager.setAdapter(PagerAdapter())

    def on_global_layout(self, recyclerView, pager):
        width = recyclerView.width
        recyclerView.set_padding(0, 0, width / 2, 0)
        pager.current_item = 0

class PagerAdapter:
    def __init__(self):
        pass

    def get_item_count(self):
        return 2

    def create_fragment(self, position):
        if position == NetworkMonitorActivity.POSITION_PEER_LIST:
            return PeerListFragment()
        elif position == NetworkMonitorActivity.POSITION_BLOCK_LIST:
            return BlockListFragment()
        else:
            raise ValueError()

class ViewPagerTabs:
    Mode = {'STATIC': 'static', 'DYNAMIC': 'dynamic'}

class ZoomOutPageTransformer:
    pass

class RecyclerView:
    def __init__(self, child):
        self.child = child
        self.clip_to_padding = False
        self.view_tree_observer().add_global_layout_listener(lambda: None)

    @property
    def width(self):
        return 0

    def set_clip_to_padding(self, value):
        self.clip_to_padding = value

class ViewPager2:
    def __init__(self):
        pass

    def get_child_at(self, position):
        return 0

    def current_item(self):
        return 0

    @property
    def user_input_enabled(self):
        return False

    def set_user_input_enabled(self, enabled):
        self.user_input_enabled = enabled

class PeerListFragment:
    pass

class BlockListFragment:
    pass