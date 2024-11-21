class DebuggerMappingOpinion:
    HIGHEST_CONFIDENCE_FIRST = lambda o: -o.confidence

    @staticmethod
    def get_endian(env):
        str_endian = env.get_endian()
        if "little" in str_endian:
            return Endian.LITTLE
        elif "big" in str_endian:
            return Endian.BIG
        else:
            return None


def query_opinions(target, include_overrides=False):
    result = []
    for opinion in ClassSearcher.get_instances(DebuggerMappingOpinion):
        try:
            offers = opinion.offers_for_env(target, include_overrides)
            with lock(result):  # equivalent to synchronized
                result.extend(offers)
        except Exception as e:
            Msg.error(DebuggerMappingOpinion, f"Problem querying opinion {opinion} for recording/mapping offers: {e}")
    result.sort(key=DebuggerMappingOpinion.HIGHEST_CONFIDENCE_FIRST)
    return result


def get_offers(self, target, include_overrides=False):
    if not isinstance(target, TargetProcess):
        return set()
    process = target
    model = process.model
    path_to_env = model.root_schema.search_for_suitable(TargetEnvironment, process.path)
    if path_to_env is None:
        Msg.error(self, "Could not find path to environment")
        return set()
    env = model.get_object(path_to_env[0])
    return self.offers_for_env(env, process, include_overrides)


def offers_for_env(self, env, process, include_overrides=False):
    pass  # This method should be implemented by the subclass


class DebuggerMappingOffer:
    def __init__(self, confidence):
        self.confidence = confidence

    @staticmethod
    def get_confidence(o):
        return o.confidence


class Endian:
    LITTLE = "little"
    BIG = "big"


from collections import defaultdict
lock = defaultdict(int)
