# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

class LocalFileUserManager:
    def __init__(self, user_dir_path):
        try:
            super().__init__(LocalFileUserAccessor(user_dir_path))
        except Exception as e:  # AuthException in Java is equivalent to Exception in Python
            raise
