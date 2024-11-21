# Copyright (c) [year] Apache Software Foundation or its licensors,
# as applicable.
#
# Licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

class VertexShapeProvider:
    """An interface that can be implemented to provide vertex shapes to the UI.  These are used
       for rendering and mouse interaction.  Typically, these shapes are the same.   Clients that
       wish to allow for complicated shapes can use this interface to control mouse hit detection
       while providing simpler shape painting.
    """

    def get_compact_shape(self) -> object:
        """Returns the compact shape that the user will see when full, detailed rendering is 
           not being performed for a vertex, such as in the satellite viewer or when fully-zoomed-out
        """
        pass

    def get_full_shape(self) -> object:
        """Returns the full (the actual) shape of a vertex.  This can be used to determine if a 
           mouse point intersects a vertex or to get the real bounding-box of a vertex.
        """
        return self.get_compact_shape()
