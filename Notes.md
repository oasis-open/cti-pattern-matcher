# Implementation Notes

This document gives some additional information regarding how the matcher is
implemented, and some usage caveats.  The emphasis in this implementation is on
simplicity, clarity, and correctness, in order to help people understand the
STIX pattern language.  It is not designed for "real" high-intensity usage.

## Background

Matching a pattern is equivalent to finding a set of *bindings*.  A binding
is a mapping from observation expressions in the pattern to observations.  The
matcher does its job in a single traversal of the pattern parse tree.  It
maintains a list of candidate bindings and other state, pruning away those which
don't work as it goes.  At the end, the result is a list of many bindings, not
just the first one found.

## Caveats

- **The number of bindings found can be large.**  If each observation
expression matches a lot of observations, the number of bindings can grow
exponentially.  In the worst case, if N observations match N observation
expressions (i.e. every observation expression matches every observation), and
only the `AND` observation operator is used, that's N! different possible
bindings altogether.

- **High repeat counts can result in a lot of bindings.**  This is related to
the previous item, but is perhaps less obvious, since the growth can occur
with even a short pattern.  It is less severe with repeat counts, since the
matcher is smart enough to collect only the distinct order-independent
*combinations*, rather than every *permutation*, as would happen if the
observation expressions had been written out without the qualifier.
Nevertheless, it can result in a lot of bindings.  As above, the thing to watch
out for is when the qualified observation expression matches a lot of
observations.

- **Temporal qualifiers are less effective at reducing the number of bindings.**
For example, using `REPEATS 5 TIMES` might result in a lot of possible bindings,
whereas `REPEATS 5 TIMES WITHIN 300 SECONDS` could allow additional temporal
filtering, reducing the number of bindings.  However, the matcher works in a
very simple way, applying each qualifier in turn.  The repetition is computed
first, then temporal filtering occurs second.  They don't occur at the same
time.  So you could still get large growth in the number of bindings in
the first step.  A more clever implementation could do both at the same time.

- **"Creative" use of references can cause large memory usage.**  This is a
corner case and unlikely to occur in a real pattern, but it's interesting.  It's
especially easy to demonstrate with circular references.  Consider the
pattern: `[foo:some_refs[*].some_refs[*].some_refs[*].some_refs[*].size > 100]`
and the observation data:
    ```json
    {
        "0": {
            "type": "foo",
            "some_refs": ["0", "1"],
            "size": 10
        },
        "1": {
            "type": "foo",
            "some_refs": ["0", "1"],
            "size": 1000
        }
    }
    ```
    The matcher handles references by substituting the referenced object for the
    reference.  So each list `["0", "1"]` is replaced with a list of the
    referenced objects.  Which themselves have two references apiece, which get
    replaced with the same objects, which have two references apiece, etc.
    Also, because of the `[*]` index steps, nothing gets pruned away; all paths
    must be considered.  This is exponential growth.

