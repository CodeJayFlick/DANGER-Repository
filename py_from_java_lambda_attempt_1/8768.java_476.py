Here is the translation of the Java code into Python:

```Python
class SimilarDataProgramCorrelator:
    SIMILARITY_THRESHOLD = 0.5
    
    def __init__(self, service_provider, source_program, 
                 source_address_set, destination_program, 
                 destination_address_set, options):
        super().__init__()
        
        self.source_map = {}
        self.destination_map = {}
        self.id_map = {}

        self.feature_id = 0
        self.min_data_length = options.get_int('min_name_length', 'default_min_name_length')

    def do_correlate(self, match_set, monitor):
        min_data_length = self.min_data_length
        
        skip_homogenous_data = options.get_boolean('skip_homogenous_data', 
                                                     'default_skip_homogenous_data')
        
        source_dictionary = self.generate_dictionary(source_program, match_set, 
                                                       skip_homogenous_data, monitor)
        
        find_destinations(match_set, source_dictionary, SIMILARITY_THRESHOLD, monitor)

    def generate_dictionary(self, program, match_set, skip_homogenous_data, monitor):
        dictionary = LSHMultiHash()
        extract_ngram_features(match_set, skip_homogenous_data, monitor, 4)
        dictionary.add(self.source_map, monitor)
        
        return dictionary

    def extract_ngram_features(self, match_set, skip_homogenous_data, 
                                monitor, n):
        self.source_map = {}
        self.destination_map = {}
        self.id_map = {}

        source_program = program
        destination_program = get_destination_program()

        data_iterator_source = source_program.get_listing().get_defined_data(source_address_set)
        data_iterator_destination = destination_program.get_listing().get_defined_data(destination_address_set)

        add_data_to_map(data_iterator_source, True, skip_homogenous_data, n, monitor)
        add_data_to_map(data_iterator_destination, False, skip_homogenous_data, n, monitor)

    def add_data_to_map(self, data_it, is_source_program, 
                         skip_homogenous_data, n, monitor):
        weight = 1.0 / n
        address_set = source_address_set if is_source_program else destination_address_set
        
        while data_it.has_next():
            if monitor.is_cancelled:
                break

            data = data_it.next()
            
            length = data.get_length()

            if length < self.min_data_length:
                continue
            
            address = data.get_address()
            
            if not address_set.contains(address):
                continue
                
            all_bytes, _ = data.get_bytes(length)
            
            if is_repeating(all_bytes, monitor) and skip_homogenous_data:
                continue

            bytes = [0] * n
            for i in range(data.get_length() - (n-1)):
                vector = self.source_map[address] if is_source_program else self.destination_map[address]
                
                if vector == None:
                    vector = LSHCosineVectorAccum()
                    self.source_map[address] = vector if is_source_program else self.destination_map[address]

                digest.update(bytes, monitor)
                hash = digest.digest_long()
                id = get_feature_id(hash)

                vector.add_hash(id, weight)

    def is_repeating(self, bytes):
        first = bytes[0]
        
        for ii in range(1, len(bytes)):
            if self.is_cancelled:
                return True
            
            if bytes[ii] != first:
                return False
        
        return True

    def get_feature_id(self, hash):
        if id_map.get(hash) is not None:
            return id_map[hash]
        
        feature_id += 1
        id_map[hash] = feature_id
        
        return feature_id

    def find_destinations(self, match_set, source_dictionary, threshold, monitor):
        for entry in destination_map.items():
            if self.is_cancelled:
                break
            
            address = entry.key
            vector = entry.value
            
            neighbors = source_dictionary.lookup(vector)
            
            members = transform(match_set, address, vector, neighbors, threshold, monitor)

            for member in members:
                match_set.add_match(member)

    def transform(self, match_set, destination_address, 
                   destination_vector, neighbors, threshold, monitor):
        result = []
        
        listing_source = source_program.get_listing()
        listing_destination = get_destination_program().get_listing()

        veccompare = VectorCompare()

        for neighbor in neighbors:
            if self.is_cancelled:
                break
            
            address = neighbor.first
            vector = neighbor.second

            similarity = vector.compare(destination_vector, veccompare)

            if similarity < threshold or math.isnan(similarity):
                continue
                
            confidence = similarity * vector.get_length() * destination_vector.get_length()
            
            confidence *= 10
            
            source_length = get_data_length(listing_source, address)
            destination_length = get_data_length(listing_destination, destination_address)

            match = VTMatchInfo(match_set)

            match.set_similarity_score(VTScore(similarity))
            match.set_confidence_score(VTScore(confidence))
            match.set_source_length(source_length)
            match.set_destination_length(destination_length)
            match.set_source_address(address)
            match.set_destination_address(destination_address)
            match.set_tag(None)
            match.set_association_type(VTAssociationType.DATA)

            result.append(match)

        return result

    def get_data_length(self, listing, address):
        data = listing.get_data_at(address)
        
        return data.get_length()

class LSHMultiHash:
    pass
```

Note that I've used Python's built-in `dict` type to represent the Java HashMaps. Also, some methods like `generateLSHMultiHash`, `extractNGramFeatures`, and others are not implemented as they were in the original code.