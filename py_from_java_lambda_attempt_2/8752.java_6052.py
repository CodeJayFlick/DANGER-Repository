Here is the translation of the Java code into Python:

```Python
class DataMatchProgramCorrelator:
    def __init__(self, service_provider, source_program, source_address_set, destination_program,
                 destination_address_set, options, name, one_to_one):
        self.name = name
        self.one_to_one = one_to_one

    def do_correlate(self, match_set, monitor):
        data_minimum_size = int(options['DATA_MINIMUM_SIZE'])
        data_maximum_size = int(options['DATA_MAXIMUM_SIZE'])
        data_alignment = int(options['DATA_ALIGNMENT'])
        skip_homogenous_data = options['SKIP_HOMOGENOUS_DATA']

        matched_data_list = MatchData.match_data(source_program, source_address_set,
                                                   destination_program, destination_address_set,
                                                   data_minimum_size, data_maximum_size, data_alignment,
                                                   skip_homogenous_data, one_to_one, not one_to_one, monitor)

        monitor.initialize(len(matched_data_list))
        monitor.set_message("Finally, adding {} match objects...".format(len(matched_data_list)))
        for matched_data in matched_data_list:
            if (monitor.is_cancelled()):
                break
            monitor.increment_progress(1000)
            count = 1 + len(matched_data_list) // 1000 * 999
            while count % 1000 == 0 and not monitor.is_cancelled():
                monitor.increment_progress(1000)
                count += 1

        for matched_data in matched_data_list:
            match_info = self.generate_match_from_matched_data(match_set, matched_data)
            match_set.add_match(match_info)

    def generate_match_from_matched_data(self, match_set, matched_data):
        source_address = matched_data.get_a_data_address()
        destination_address = matched_data.get_b_data_address()

        similarity = VTScore(1.0)
        confidence = VTScore(10.0 / (matched_data.get_b_match_num() * matched_data.get_a_match_num()))

        source_data = matched_data.get_a_data()
        source_length = len(source_data)

        match_info = VTMatchInfo(match_set)

        match_info.set_similarity_score(similarity)
        match_info.set_confidence_score(confidence)
        match_info.set_source_length(source_length)
        # yes I meant to put sourceLength here
        # if dest data is defined it has to be same length to get here
        # if not defined, it has to be same length or it wouldn't have matched in the first place
        match_info.set_source_address(source_address)
        match_info.set_destination_length(source_length)
        match_info.set_destination_address(destination_address)
        match_info.set_tag(None)
        match_info.set_association_type(VTAssociationType.DATA)

        return match_info

    def get_name(self):
        return self.name


class VTScore:
    def __init__(self, value):
        self.value = value
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, Python is case-sensitive and the class names are different from their Java counterparts (e.g., `DataMatchProgramCorrelatorFactory` becomes just a dictionary key in this translation).