# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import recompute_field_value as rfv

class Target_org_rocksdb_NativeLibraryLoader:
    initialized = False

rfv.alias(Target_org_rocksdb_NativeLibraryLoader.initialized)
rfv.recompute_field_value(kind=rvf.RecomputeFieldValueKind.RESET, field_name='initialized')

# Inspired by https://github.com/quarkusio/quarkus/blob/main/extensions/kafka-streams/runtime/src/main/java/io/quarkus/kafka/streams/runtime/graal/KafkaStreamsSubstitutions.java

class RocksSubstitutions:
    pass
