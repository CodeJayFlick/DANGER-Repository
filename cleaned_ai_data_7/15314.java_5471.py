# Copyright Andreas Schildbach or other original authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import io

class Assets:
    @staticmethod
    def open(assets: 'io.AssetManager', filename: str):
        try:
            return assets.open(filename)
        except Exception as x:
            raise SystemExit(x)

