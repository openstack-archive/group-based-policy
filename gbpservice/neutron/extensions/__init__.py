GBP_PLURALS = {}


def register_plurals(plural_mappings):
    for plural, single in plural_mappings.items():
        GBP_PLURALS[single] = plural


def get_plural(single):
    return GBP_PLURALS.get(single)
