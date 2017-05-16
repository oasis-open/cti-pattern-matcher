import antlr4

import stix2patterns.pattern
import stix2matcher.matcher

class Pattern(stix2patterns.pattern.Pattern):
    """
    Represents a pattern in a "compiled" form, for more efficient reuse.
    """

    def match(self, observed_data_sdos, verbose=False):
        """
        Match this pattern against the given observations.  Returns matching
        SDOs.  The matcher can find many bindings; this function returns the
        SDOs corresponding to only the first binding found.

        :param observed_data_sdos: A list of observed-data SDOs, as a list of
            dicts.  STIX JSON should be parsed into native Python structures
            before calling this function.
        :param verbose: Whether to dump detailed info about matcher operation
        :return: Matching SDOs if the pattern matched; an empty list if it
            didn't match.
        :raises stix2matcher.matcher.MatcherException: If an error occurs 
            during matching
        """
        matcher = stix2matcher.matcher.MatchListener(observed_data_sdos,
                                                     verbose)
        antlr4.ParseTreeWalker.DEFAULT.walk(matcher, self.__parse_tree)

        found_bindings = matcher.matched()
        if found_bindings:
            matching_sdos = matcher.get_sdos_from_binding(found_bindings[0])
        else:
            matching_sdos = []

        return matching_sdos
