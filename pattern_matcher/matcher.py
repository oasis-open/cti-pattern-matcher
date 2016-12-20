from __future__ import print_function

import argparse
import datetime
import dateutil.relativedelta
import dateutil.tz
import io
import itertools
import json
import operator
import pprint
import re
import six
import socket
import struct
import sys

import antlr4
import antlr4.error.Errors
import antlr4.error.ErrorListener

from pattern_matcher.grammars.CyboxPatternListener import CyboxPatternListener
from pattern_matcher.grammars.CyboxPatternLexer import CyboxPatternLexer
from pattern_matcher.grammars.CyboxPatternParser import CyboxPatternParser


# Example cybox-container.  Note that these have no timestamps.
# Those are assigned externally to CybOX.  A container plus a
# timestamp is an "observation".
#
# {
#   "type":"cybox-container",
#   "spec_version":"3.0",
#   "objects":{
#     "0":{
#       "type":"file-object",
#       "hashes":{
#         "sha-256":"bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52"
#       }
#     },
#     "1":{
#       "type":"file-object",
#       "hashes":{
#         "md5":"22A0FB8F3879FB569F8A3FF65850A82E"
#       }
#     },
#     "2":{
#       "type":"file-object",
#       "hashes":{
#         "md5":"8D98A25E9D0662B1F4CA3BF22D6F53E9"
#       }
#     },
#     "3":{
#       "type":"file-object",
#       "hashes":{
#         "sha-256":"aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb00"
#       },
#       "mime_type":"application/zip",
#       "extended_properties":{
#         "archive":{
#           "file_refs":[
#             "0",
#             "1",
#             "2"
#           ],
#           "version":"5.0"
#         }
#       }
#     }
#   }
# }


# Coercers from strings (what all token values are) to python types.
# Set and regex literals are not handled here; they're a different beast...
_TOKEN_TYPE_COERCERS = {
    CyboxPatternParser.IntLiteral: int,
    # for strings, strip quotes and un-escape embedded quotes
    CyboxPatternParser.StringLiteral: lambda s: s[1:-1].replace("''", "'"),
    CyboxPatternParser.BoolLiteral: bool,
    CyboxPatternParser.FloatLiteral: float,
    CyboxPatternParser.NULL: lambda _: None
}


# Map python types to 2-arg equality functions.  The functions must return
# True if equal, False otherwise.  It's mostly the same thing for now,
# but perhaps would provide a convenient place to hook in alternative
# equality checkers if necessary?
#
# This table may be treated symmetrically via _get_table_symmetric() below.
# (I only added half the entries since I plan to use that.)  And of course,
# that means all the functions in the table must be insensitive to the order
# of types of their arguments.
#
# Since I use python operators, python's mixed-type comparison rules are
# in effect, e.g. conversion of operands to a common type.
_NoneType = type(None)  # better way to do this??


def _ret_false(_1, _2):
    return False


def _ret_true(_1, _2):
    return True


_COMPARE_EQ_FUNCS = {
    int: {
        int: operator.eq,
        float: operator.eq
    },
    float: {
        float: operator.eq
    },
    six.binary_type: {
        six.binary_type: operator.eq,
        six.text_type: operator.eq
    },
    six.text_type: {
        six.text_type: operator.eq
    },
    bool: {
        bool: operator.eq
    },
    _NoneType: {
        _NoneType: _ret_true
    }
}


# Similar for <, >, etc comparisons.  These functions should return <0 if
# first arg is less than second; 0 if equal, >0 if first arg is greater.
# It's all the same thing for now (cmp)... but perhaps would provide a
# convenient place to hook in alternative comparators if necessary?
#
# This table may be treated symmetrically via _get_table_symmetric() below.
# (I only added half the entries since I plan to use that.)  And of course,
# that means all the functions in the table must be insensitive to the order
# of types of their arguments.
#
# Since I use python operators, python's mixed-type comparison rules are
# in effect, e.g. conversion of operands to a common type.
#
# cmp() was removed in Python 3. See
# https://docs.python.org/3.0/whatsnew/3.0.html#ordering-comparisons
def _cmp(a, b):
    return (a > b) - (a < b)


_COMPARE_ORDER_FUNCS = {
    int: {
        int: _cmp,
        float: _cmp
    },
    float: {
        float: _cmp
    },
    six.binary_type: {
        six.binary_type: _cmp,
        six.text_type: _cmp
    },
    six.text_type: {
        six.text_type: _cmp
    }
}


class MatcherException(Exception):
    """Base class for matcher exceptions."""
    pass


class MatcherInternalError(MatcherException):
    """For errors that probably represent bugs or incomplete matcher
    implementation."""
    pass


class UnsupportedOperatorError(MatcherInternalError):
    """This means I just haven't yet added support for a particular operator.
    (A genuinely invalid operator ought to be caught during parsing right??)
    I found I was throwing internal errors for this in several places, so I
    just gave the error its own class to make it easier.
    """
    def __init__(self, op_str):
        super(UnsupportedOperatorError, self).__init__(
            "Unsupported operator: '{}'".format(op_str)
        )


class TypeMismatchException(MatcherException):
    """Represents some kind of type mismatch when evaluating a pattern
    against some data.
    """
    def __init__(self, cmp_op, type_from_cybox_json, literal_type):
        """
        Initialize the exception object.

        :param cmp_op: The comparison operator as a string, e.g. "<="
        :param type_from_cybox_json: A python type instance
        :param literal_type: A token type (which is an int)
        """
        super(TypeMismatchException, self).__init__(
            "Type mismatch in '{}' operation: json={}, pattern={}".format(
                cmp_op,
                type_from_cybox_json,
                CyboxPatternParser.symbolicNames[literal_type]
            )
        )


class MatcherErrorListener(antlr4.error.ErrorListener.ErrorListener):
    """
    Simple error listener which just remembers the last error message received.
    """
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.error_message = msg


def _get_table_symmetric(table, val1, val2):
    """
    Gets an operator from a table according to the given types.  This
    gives the illusion of a symmetric matrix, e.g. if tbl[a][b] doesn't exist,
    tbl[b][a] is automatically tried.  That means you only have to fill out
    half of the given table.  (The "table" is a nested dict.)
    """
    tmp = table.get(val1)
    if tmp is None:
        # table[val1] is missing; try table[val2]
        tmp = table.get(val2)
        if tmp is None:
            return None
        return tmp.get(val1)
    else:
        # table[val1] is there.  But if table[val1][val2] is missing,
        # we still gotta try it the other way.
        tmp = tmp.get(val2)
        if tmp is not None:
            return tmp

        # gotta try table[val2][val1] now.
        tmp = table.get(val2)
        if tmp is None:
            return None
        return tmp.get(val1)


def _step_into_objs(objs, step):
    """
    'objs' is a list of cybox (sub)structures.  'step' describes a
    step into the structure, relative to the top level: if an int, we
    assume the top level is a list, and the int is a list index.  If
    a string, assume the top level is a dict, and the string is a key.
    If a structure is such that the step can't be taken (e.g. the dict
    doesn't have the particular key), filter the value from the list.

    :return: A new list containing the "stepped-into" structures, minus
       any structures which couldn't be stepped into.
    """

    stepped_cybox_objs = []
    if isinstance(step, int):
        for obj in objs:
            if isinstance(obj, list) and step < len(obj):
                stepped_cybox_objs.append(obj[step])
            # can't index non-lists
    elif isinstance(step, six.string_types):
        for obj in objs:
            if isinstance(obj, dict) and step in obj:
                stepped_cybox_objs.append(obj[step])
            # can't do key lookup in non-dicts

    else:
        raise MatcherInternalError(
            "Unsupported step type: {}".format(type(step)))

    return stepped_cybox_objs


def _step_filter_observations(observations, step):
    """
    A helper for the listener.  Given a particular structure in 'observations'
    (see exitObjectType(), exitFirstPathComponent()), representing a set
    of observations and partial path stepping state, do a pass over all the
    observations, attempting to take the given step on all of their cybox
    objects (or partial cybox object structures).

    :return: a filtered observation map: it includes those for which at
      least one contained cybox object was successfully stepped.  If none
      of an observation's cybox objects could be successfully stepped,
      the observation is dropped.
    """

    filtered_obs_map = {}
    for obs_idx, cybox_obj_map in six.iteritems(observations):
        filtered_cybox_obj_map = {}
        for cybox_obj_id, cybox_objs in six.iteritems(cybox_obj_map):
            filtered_cybox_obj_list = _step_into_objs(cybox_objs, step)

            if len(filtered_cybox_obj_list) > 0:
                filtered_cybox_obj_map[cybox_obj_id] = filtered_cybox_obj_list

        if len(filtered_cybox_obj_map) > 0:
            filtered_obs_map[obs_idx] = filtered_cybox_obj_map

    return filtered_obs_map


def _step_filter_observations_index_star(observations):
    """
    Does an index "star" step, i.e. "[*]".  This will pull out all elements
    of the list as if they were parts of separate cybox objects, which
    has the desired effect for matching: if any list elements match the
    remainder of the pattern, they are selected for the subsequent property
    test.  As usual, non-lists at this point are dropped, and observations
    for whom all cybox (sub)structure was dropped, are also dropped.

    See also _step_filter_observations().
    """

    filtered_obs_map = {}
    for obs_idx, cybox_obj_map in six.iteritems(observations):
        filtered_cybox_obj_map = {}
        for cybox_obj_id, cybox_objs in six.iteritems(cybox_obj_map):
            stepped_cybox_objs = []
            for cybox_obj in cybox_objs:
                if not isinstance(cybox_obj, list):
                    continue

                stepped_cybox_objs.extend(cybox_obj)

            if len(stepped_cybox_objs) > 0:
                filtered_cybox_obj_map[cybox_obj_id] = stepped_cybox_objs

        if filtered_cybox_obj_map:
            filtered_obs_map[obs_idx] = filtered_cybox_obj_map

    return filtered_obs_map


def _get_first_terminal_descendant(ctx):
    """
    Gets the first terminal descendant of the given parse tree node.
    I use this with nodes for literals to get the actual literal terminal
    node, from which I can get the literal value itself.
    """
    if isinstance(ctx, antlr4.TerminalNode):
        return ctx

    # else, it's a RuleContext
    term = None
    for child in ctx.getChildren():
        term = _get_first_terminal_descendant(child)
        if term is not None:
            break

    return term


def _literal_terminal_to_python_val(literal_terminal):
    """
    Use the table of "coercer" functions to convert a terminal node from the
    parse tree to a Python value.
    """
    token_type = literal_terminal.getSymbol().type

    if token_type in _TOKEN_TYPE_COERCERS:
        coercer = _TOKEN_TYPE_COERCERS[token_type]
        python_value = coercer(literal_terminal.getText())
    else:
        raise MatcherInternalError("Unsupported literal type: {}".format(
            CyboxPatternParser.symbolicNames[token_type]))

    return python_value


def _like_to_regex(like):
    """Convert a "like" pattern to a regex."""

    with io.StringIO() as sbuf:
        # "like" always must match the whole string, so surround with anchors
        sbuf.write(u"^")
        for c in like:
            if c == u"%":
                sbuf.write(u".*")
            elif c == u"_":
                sbuf.write(u".")
            else:
                if not c.isalnum():
                    sbuf.write(u'\\')
                sbuf.write(c)
        sbuf.write(u"$")
        s = sbuf.getvalue()

    # print(like, "=>", s)
    return s


def _str_to_datetime(timestamp_str):
    """
    Convert a timestamp string from a pattern to a datetime.datetime object.
    If conversion fails, return None.
    """

    # Can't create a pattern with an optional part... so make two patterns
    # and try both.
    format = "%Y-%m-%dT%H:%M:%SZ"
    format_frac = "%Y-%m-%dT%H:%M:%S.%fZ"

    dt = None
    try:
        dt = datetime.datetime.strptime(timestamp_str, format)
        # strptime doesn't seem to have a format specifier for the 'Z'
        # in isoformat strings... so just set utc timezone directly.
        dt = dt.replace(tzinfo=dateutil.tz.tzutc())
    except ValueError:
        pass

    if dt is None:
        try:
            dt = datetime.datetime.strptime(timestamp_str, format_frac)
            dt = dt.replace(tzinfo=dateutil.tz.tzutc())
        except ValueError:
            pass

    return dt


def _ip_addr_to_int(ip_str):
    """
    Converts a dotted-quad IP address string to an int.  The int is equal
    to binary representation of the four bytes in the address concatenated
    together, in the order they appear in the address.  E.g.

        1.2.3.4

    converts to

        00000001 00000010 00000011 00000100
      = 0x01020304
      = 16909060 (decimal)
    """
    try:
        ip_bytes = socket.inet_aton(ip_str)
    except socket.error:
        raise MatcherException("Invalid IPv4 address: {}".format(ip_str))

    int_val, = struct.unpack(">I", ip_bytes)  # unsigned big-endian

    return int_val


def _cidr_subnet_to_ints(subnet_cidr):
    """
    Converts a CIDR style subnet string to a 2-tuple of ints.  The
    first element is the IP address portion as an int, and the second
    is the prefix size.
    """

    slash_idx = subnet_cidr.find("/")
    if slash_idx == -1:
        raise MatcherException("Invalid CIDR subnet: {}".format(subnet_cidr))

    ip_str = subnet_cidr[:slash_idx]
    prefix_str = subnet_cidr[slash_idx+1:]

    ip_int = _ip_addr_to_int(ip_str)
    if not prefix_str.isdigit():
        raise MatcherException("Invalid CIDR subnet: {}".format(subnet_cidr))
    prefix_size = int(prefix_str)

    if prefix_size < 1 or prefix_size > 32:
        raise MatcherException("Invalid CIDR subnet: {}".format(subnet_cidr))

    return ip_int, prefix_size


def _ip_or_cidr_in_subnet(ip_or_cidr_str, subnet_cidr):
    """
    Determine if the IP or CIDR subnet given in the first arg, is contained
    within the CIDR subnet given in the second arg.

    :param ip_or_cidr_str: An IP address as a string in dotted-quad notation,
        or a subnet as a string in CIDR notation
    :param subnet_cidr: A subnet as a string in CIDR notation
    """

    # First arg is the containee, second is the container.  Does the
    # container contain the containee?

    # Handle either plain IP or CIDR notation for the containee.
    slash_idx = ip_or_cidr_str.find("/")
    if slash_idx == -1:
        containee_ip_int = _ip_addr_to_int(ip_or_cidr_str)
        containee_prefix_size = 32
    else:
        containee_ip_int, containee_prefix_size = _cidr_subnet_to_ints(
            ip_or_cidr_str)

    container_ip_int, container_prefix_size = _cidr_subnet_to_ints(subnet_cidr)

    if container_prefix_size > containee_prefix_size:
        return False

    # Use container mask for both IPs
    container_mask = ((1 << container_prefix_size) - 1) << \
                     (32 - container_prefix_size)
    masked_containee_ip = containee_ip_int & container_mask
    masked_container_ip = container_ip_int & container_mask

    return masked_containee_ip == masked_container_ip


def _disjoint(first_seq, *rest_seq):
    """
    Checks whether the values in first sequence are disjoint from the
    values in the sequences in rest_seq.

    :return: True if first_seq is disjoint from the rest, False otherwise.
    """

    if len(rest_seq) == 0:
        return True

    # is there a faster way to do this?
    fs = set(first_seq)
    return all(
        fs.isdisjoint(set(seq))
        for seq in rest_seq
    )


def _timestamps_within(timestamps, duration):
    """
    Checks whether the given timestamps are within the given duration, i.e.
    the difference between the earliest and latest is <= the duration.

    :param timestamps: An iterable of timestamps (datetime.datetime)
    :param duration: A duration (dateutil.relativedelta.relativedelta).
    :return: True if the timestamps are within the given duration, False
        otherwise.
    """

    earliest_timestamp = None
    latest_timestamp = None
    for timestamp in timestamps:
        if earliest_timestamp is None or timestamp < earliest_timestamp:
            earliest_timestamp = timestamp
        if latest_timestamp is None or timestamp > latest_timestamp:
            latest_timestamp = timestamp

    result = (earliest_timestamp + duration) >= latest_timestamp

    return result


def _dereference_cybox_objs(cybox_objs, cybox_obj_references, ref_prop_name):
    """
    Dereferences a sequence of cybox object references.  Returns a list of
    the referenced objects.  If a reference does not resolve, it is not
    treated as an error, it is ignored.

    :param cybox_objs: The context for reference resolution.  This is a mapping
        from cybox object ID to cybox object, i.e. the "objects" property of
        a container.
    :param cybox_obj_references: An iterable of cybox object references.  These
        must all be strings, otherwise an exception is raised.
    :param ref_prop_name: For better error messages, the reference property
        being processed.
    :return: A list of the referenced cybox objects.  This could be fewer than
        the number of references, if some references didn't resolve.
    """
    dereferenced_cybox_objs = []
    for referenced_obj_id in cybox_obj_references:
        if not isinstance(referenced_obj_id, six.string_types):
            raise MatcherException(
                "{} value of reference property '{}' was not "
                "a string!  Got {}".format(
                    # Say "A value" if the property is a reference list,
                    # otherwise "The value".
                    "A" if ref_prop_name.endswith("_refs") else "The",
                    ref_prop_name, referenced_obj_id
                ))

        if referenced_obj_id in cybox_objs:
            dereferenced_cybox_objs.append(cybox_objs[referenced_obj_id])

    return dereferenced_cybox_objs


def _obs_map_prop_test(obs_map, predicate):
    """
    Property tests always perform the same structural transformation of
    observation data on the stack.  There are several callbacks within the
    matcher listener to do various types of tests, and I found I was having to
    update the same basic code in many places.  So I have factored it out to
    this function.  As the pattern design evolves and my program changes, the
    data structures and required transformations evolve too.  This gives me a
    single place to update one of these transformations, instead of having to
    do it repeatedly in N different places.  It also gives a nice centralized
    place to document it.

    Required structure for obs_map is the result of object path selection;
    see MatchListener.exitObjectPath() for details.

    The structure of the result of a property test is:

    {
      obs_idx: {cybox_obj_id1, cybox_obj_id2, ...},
      obs_idx: {cybox_obj_id1, cybox_obj_id2, ...},
      etc...
    }

    I.e. for each observation, a set of cybox object IDs is associated, which
    are the "root" objects which caused the match.  The cybox object ID info
    is necessary to eliminate observation expression matches not rooted at the
    same cybox object.

    :param obs_map: Observation data, as selected by an object path.
    :param predicate: This encompasses the actual test to perform.  It must
        be a function of one parameter, which returns True or False.
    :return: The transformed and filtered data, according to predicate.
    """
    passed_obs = {}
    for obs_idx, cybox_obj_map in six.iteritems(obs_map):
        passed_cybox_obj_roots = set()
        for cybox_obj_id, values in six.iteritems(cybox_obj_map):
            for value in values:
                if predicate(value):
                    passed_cybox_obj_roots.add(cybox_obj_id)
                    break

        if passed_cybox_obj_roots:
            passed_obs[obs_idx] = passed_cybox_obj_roots

    return passed_obs


def _filtered_combinations(values, combo_size, filter_pred=None):
    """
    Finds combinations of values of the given size, from the given sequence,
    filtered according to the given predicate.

    This function builds up the combinations incrementally, and the predicate
    is invoked with partial results.  This allows many combinations to be
    ruled out early.  If the predicate returns True, the combination is kept,
    otherwise it is discarded.

    The predicate is invoked with each combination value as a separate
    argument.  E.g. if (1,2,3) is a candidate combination (or partial
    combination), the predicate is invoked as pred(1, 2, 3).  So the predicate
    will probably need a "*args"-style argument for capturing variable
    numbers of positional arguments.

    Because of the way combinations are built up incrementally, the predicate
    may assume that args 1 through N already satisfy the predicate (they've
    already been run through it), which may allow you to optimize the
    implementation.  Arg 0 is the "new" arg being tested to see if can be
    prepended to the rest of the args.

    :param values: The sequence of values
    :param combo_size: The desired combination size (must be >= 1)
    :param filter_pred: The filter predicate.  If None (the default), no
        filtering is done.
    :return: The combinations, as a list of tuples.
    """

    if combo_size < 1:
        raise ValueError("combo_size must be >= 1")
    elif combo_size > len(values):
        # Not enough values to make any combo
        return []
    elif combo_size == 1:
        # Each value is its own combo
        return [(value,) for value in values
                if filter_pred is None or filter_pred(value)]
    else:

        sub_combos = _filtered_combinations(values[1:], combo_size - 1,
                                            filter_pred)

        combos = [(values[0],) + sub_combo
                  for sub_combo in sub_combos
                  if filter_pred is None or filter_pred(values[0], *sub_combo)]

        combos += _filtered_combinations(values[1:], combo_size, filter_pred)

        return combos


class MatchListener(CyboxPatternListener):
    """
    A parser listener which performs pattern matching.  It works like an
    RPN calculator, pushing and popping intermediate results to/from an
    internal stack as the parse tree is traversed.  I tried to document
    for each callback method, what it consumes from the stack, and kind of
    values it produces.

    Matching a pattern is equivalent to finding a set of "bindings": an
    observation "bound" to each observation expression such that the
    constraints embodied in the pattern are satisfied.  The final value
    on top of the stack after the pattern matching process is complete contains
    these bindings.  If any bindings were found, the pattern matched, otherwise
    it didn't match.  (Assuming there were no errors during the matching
    process, of course.)

    There are different ways of doing this; one obvious way is a depth-first
    search, where you try different bindings, and backtrack to earlier
    decision points as you hit dead-ends.  I had originally been aiming to
    perform a complete pattern matching operation in a single post-order
    traversal of the parse tree, which means no backtracking.  So this matcher
    is implemented in a different way.  It essentially tracks all possible
    bindings at once, pruning away those which don't work as it goes.  This
    will likely use more memory, and the bookkeeping is a bit more complex,
    but it only needs one pass through the tree.  And at the end, you get
    *all possible* bindings, rather than just the first one found, as might
    be the case with a backtracking algorithm.
    """

    def __init__(self, observations, timestamps, verbose=False):
        """
        Initialize this match listener.

        :param observations: A list of cybox containers.
        :param timestamps: A list of timestamps, as timezone-aware
            datetime.datetime objects.  If these are not "aware" objects,
            comparisons with other timestamps in patterns will fail.  There
            must be the same number of timestamps, as containers.  They
            correspond to each other: the i'th timestamp is for the i'th
            container.
        :param verbose: If True, dump detailed information about triggered
            callbacks and stack activity to stdout.  This can provide useful
            information about what the matcher is doing.
        """
        self.__observations = observations
        self.__timestamps = timestamps

        # Need one timestamp per observation
        assert len(self.__observations) == len(self.__timestamps)

        self.__verbose = verbose
        # Holds intermediate results
        self.__compute_stack = []

    def __push(self, val, label=None):
        """Utility for pushing a value onto the compute stack.
        In verbose mode, show what's being pushed.  'label' lets you prefix
        the message with something... e.g. I imagine using a parser rule name.
        """
        self.__compute_stack.append(val)

        if self.__verbose:
            if label:
                print("{}: ".format(label), end="")
            print("push {}".format(pprint.pformat(val)))

    def __pop(self, label=None):
        """Utility for popping a value off the compute stack.
        In verbose mode, show what's being popped.  'label' lets you prefix
        the message with something... e.g. I imagine using a parser rule name.
        """
        val = self.__compute_stack.pop()

        if self.__verbose:
            if label:
                print("{}: ".format(label), end="")
            print("pop {}".format(pprint.pformat(val)))

        return val

    def matched(self):
        """
        After a successful parse, this will tell you whether the pattern
        matched its input.  You should only call this if the parse succeeded.
        """
        # At the end of the parse, the top stack element will be a list of
        # all the found bindings (as tuples).  If there is at least one, the
        # pattern matched.  If the parse failed, the top stack element could
        # be anything... so don't call this function in that situation!
        return (len(self.__compute_stack) > 0 and
                len(self.__compute_stack[0]) > 0)

    def exitObservationExpressions(self, ctx):
        """
        If there is no ALONGWITH or FOLLOWEDBY operator, this callback does
        nothing.  Otherwise:

        Consumes two lists of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined list of binding tuples.  This essentially produces a
          filtered cartesian cross-product of the LHS and RHS tuples.
          - If ALONGWITH is the operator, they're combined in all different ways
            such that a joined tuple has no duplicate observation IDs.
          - If FOLLOWEDBY is the operator, then in addition to the above
            restriction, the timestamps on the RHS binding must be >= than the
            timestamps on the LHS binding.
        """
        num_operands = len(ctx.observationExpressions())

        if num_operands not in (0, 2):
            # Just in case...
            msg = "Unexpected number of observationExpressions children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 2:
            op_str = ctx.getChild(1).getText()
            debug_label = "exitObservationExpressions ({})".format(op_str)

            rhs_bindings = self.__pop(debug_label)
            lhs_bindings = self.__pop(debug_label)

            joined_bindings = []
            for lhs_binding in lhs_bindings:

                # Precompute latest lhs timestamp if this is a FOLLOWEDBY
                # operator, so we can reuse later.
                if ctx.FOLLOWEDBY():
                    latest_lhs_timestamp = max(
                        self.__timestamps[obs_id] for obs_id in lhs_binding
                    )

                for rhs_binding in rhs_bindings:

                    if _disjoint(lhs_binding, rhs_binding):
                        if ctx.ALONGWITH():
                            joined_bindings.append(lhs_binding + rhs_binding)

                        elif ctx.FOLLOWEDBY():
                            # make sure the rhs timestamps are later (or equal)
                            # than all lhs timestamps.
                            earliest_rhs_timestamp = min(
                                self.__timestamps[obs_id] for obs_id in rhs_binding
                            )

                            if latest_lhs_timestamp <= earliest_rhs_timestamp:
                                joined_bindings.append(lhs_binding +
                                                       rhs_binding)

                        else:
                            raise UnsupportedOperatorError(op_str)

            self.__push(joined_bindings, debug_label)

        # If only the one observationExpression child, we don't need to do
        # anything to the top of the stack.

    def exitObservationExpressionSimple(self, ctx):
        """
        Consumes a the results of the inner comparison expression.  See
        exitComparisonExpression().
        Produces: a list of 1-tuples of the IDs.  At this stage, the root
        cybox object IDs are no longer needed, and are dropped.

        This is a preparatory transformative step, so that higher-level
        processing has consistent structures to work with (always lists of
        tuples).
        """

        debug_label = "exitObservationExpression (simple)"
        obs_ids = self.__pop(debug_label)
        obs_id_tuples = [(obs_id,) for obs_id in obs_ids.keys()]
        self.__push(obs_id_tuples, debug_label)

    # Don't need to do anything for exitObservationExpressionCompound

    def exitObservationExpressionRepeated(self, ctx):
        """
        Consumes a list of bindings for the qualified observation expression.
        Produces a list of bindings which account for the repetition.  The
          length of each new binding is equal to the length of the old bindings
          times the repeat count.
        """

        rep_count = _literal_terminal_to_python_val(
            ctx.repeatedQualifier().IntLiteral()
        )
        debug_label = "exitObservationExpressionRepeated ({})".format(
            rep_count
        )

        bindings = self.__pop(debug_label)

        # Need to find all 'rep_count'-sized disjoint combinations of
        # bindings.
        if rep_count < 1:
            raise MatcherException("Invalid repetition count: {}".format(
                rep_count))
        elif rep_count == 1:
            # As an optimization, if rep_count is 1, we use the bindings
            # as-is.
            filtered_bindings = bindings
        else:
            # A list of tuples goes in (bindings)
            filtered_bindings = _filtered_combinations(bindings, rep_count,
                                                       _disjoint)
            # ... and a list of tuples of tuples comes out
            # (filtered_bindings).  The following flattens each outer
            # tuple.  I could have also written a generic flattener, but
            # since this structure is predictable, I could do something
            # simpler.  Other code dealing with bindings doesn't expect any
            # nested structure, so I do the flattening here.
            filtered_bindings = [tuple(itertools.chain.from_iterable(binding))
                                 for binding in filtered_bindings]

        self.__push(filtered_bindings, debug_label)

    def exitObservationExpressionWithin(self, ctx):
        """
        Consumes (1) a duration, as a dateutil.relativedelta,relativedelta
          object (see exitWithinQualifier()), and (2) a list of bindings.
        Produces a list of bindings which are temporally filtered according
          to the given duration.
        """

        debug_label = "exitObservationExpressionWithin"

        duration = self.__pop(debug_label)
        bindings = self.__pop(debug_label)

        filtered_bindings = []
        for binding in bindings:
            if _timestamps_within(
                    (self.__timestamps[obs_id] for obs_id in binding),
                    duration):
                filtered_bindings.append(binding)

        self.__push(filtered_bindings, debug_label)

    def exitObservationExpressionStartStop(self, ctx):
        """
        Consumes (1) a time interval as a pair of datetime.datetime objects,
          and (2) a list of bindings.
        Produces a list of bindings which are temporally filtered according
          to the given time interval.
        """

        debug_label = "exitObservationExpressionStartStop"

        # In this case, these are start and stop timestamps as
        # datetime.datetime objects (see exitStartStopQualifier()).
        start_time, stop_time = self.__pop(debug_label)
        bindings = self.__pop(debug_label)

        filtered_bindings = []
        for binding in bindings:
            in_bounds = all(
                start_time <= self.__timestamps[obs_id] < stop_time
                for obs_id in binding
            )

            if in_bounds:
                filtered_bindings.append(binding)

        self.__push(filtered_bindings, debug_label)

    def exitStartStopQualifier(self, ctx):
        """
        Consumes nothing
        Produces a (datetime, datetime) 2-tuple containing the start and stop
          times.
        """

        start_str = _literal_terminal_to_python_val(ctx.StringLiteral(0))
        stop_str = _literal_terminal_to_python_val(ctx.StringLiteral(1))

        start_dt = _str_to_datetime(start_str)
        if start_dt is None:
            raise MatcherException("Invalid timestamp format: {}".format(start_str))

        stop_dt = _str_to_datetime(stop_str)
        if stop_dt is None:
            raise MatcherException("Invalid timestamp format: {}".format(stop_str))

        self.__push((start_dt, stop_dt), "exitStartStopQualifier")

    def exitWithinQualifier(self, ctx):
        """
        Consumes a unit string, produced by exitTimeUnit().
        Produces a dateutil.relativedelta.relativedelta object, representing
          the specified interval.
        """

        debug_label = "exitWithinQualifier"
        unit = self.__pop(debug_label)
        value = _literal_terminal_to_python_val(ctx.IntLiteral())
        if value < 0:
            raise MatcherException("Invalid WITHIN value: {}".format(value))

        if unit == "years":
            delta = dateutil.relativedelta.relativedelta(years=value)
        elif unit == "months":
            delta = dateutil.relativedelta.relativedelta(months=value)
        elif unit == "days":
            delta = dateutil.relativedelta.relativedelta(days=value)
        elif unit == "hours":
            delta = dateutil.relativedelta.relativedelta(hours=value)
        elif unit == "minutes":
            delta = dateutil.relativedelta.relativedelta(minutes=value)
        elif unit == "seconds":
            delta = dateutil.relativedelta.relativedelta(seconds=value)
        elif unit == "milliseconds":
            delta = dateutil.relativedelta.relativedelta(microseconds=value*1000)
        else:
            raise MatcherException("Unsupported WITHIN unit: {}".format(unit))

        self.__push(delta, debug_label)

    def exitTimeUnit(self, ctx):
        """
        Consumes nothing
        Produces the time unit (e.g. "days", "hours", etc) converted to
          lower case.
        """
        unit = ctx.getText().lower()
        self.__push(unit, "exitTimeUnit")

    def exitComparisonExpression(self, ctx):
        """
        Consumes zero or two maps of observation IDs produced by child
          propTest's (see _obs_map_prop_test()) and/or
          sub-comparison-expressions.
        Produces: if one child expression, this callback does nothing.  If
          two, the top two maps on the stack are combined into a single map of
          observation IDs.

          This implements the "OR" operator.  So the maps are merged (union);
          observation IDs which are shared between both operands have their
          cybox object ID sets unioned in the result.
        """

        debug_label = "exitComparisonExpression"
        num_or_operands = len(ctx.comparisonExpression())

        # Just in case...
        if num_or_operands not in (0, 2):
            msg = "Unexpected number of comparisonExpression children: {}"
            raise MatcherInternalError(msg.format(num_or_operands))

        if num_or_operands == 2:
            # The result is collected into obs1.
            obs2 = self.__pop(debug_label)
            obs1 = self.__pop(debug_label)

            # We union the observation IDs and their corresponding
            # cybox object ID sets.
            for obs_id, cybox_obj_ids in six.iteritems(obs2):
                if obs_id in obs1:
                    obs1[obs_id] |= cybox_obj_ids
                else:
                    obs1[obs_id] = cybox_obj_ids

            self.__push(obs1, debug_label)

    def exitComparisonExpressionAnd(self, ctx):
        """
        Consumes zero or two maps of observation IDs produced by child
          propTest's (see _obs_map_prop_test()) and/or
          sub-comparison-expressions.
        Produces: if one child expression, this callback does nothing.  If
          two, the top two maps on the stack are combined into a single map of
          observation IDs.

          This implements the "AND" operator.  So the result map has those IDs
          common to both (intersection); their cybox object ID sets are also
          intersected.  If this latter intersection is empty, the corresponding
          observation is dropped.
        """

        debug_label = "exitComparisonExpressionAnd"
        num_and_operands = len(ctx.comparisonExpressionAnd())

        # Just in case...
        if num_and_operands not in (0, 2):
            msg = "Unexpected number of comparisonExpression children: {}"
            raise MatcherInternalError(msg.format(num_and_operands))

        if num_and_operands == 2:
            # The result is collected into obs1.
            obs2 = self.__pop(debug_label)
            obs1 = self.__pop(debug_label)

            # We intersect the observation IDs and their corresponding
            # cybox object ID sets.  If any of the cybox object ID set
            # intersections is empty, we drop the observation from the
            # result.
            obs_ids_to_drop = []
            for obs_id, cybox_obj_ids in six.iteritems(obs1):
                if obs_id in obs2:
                    obs1[obs_id] &= obs2[obs_id]
                    if not obs1[obs_id]:
                        obs_ids_to_drop.append(obs_id)
                else:
                    obs_ids_to_drop.append(obs_id)

            # Now drop the ones we found (can't modify as we iterated
            # above, so this needs to be a separate pass).
            for obs_id in obs_ids_to_drop:
                del obs1[obs_id]

            self.__push(obs1, debug_label)

    def exitPropTestEqual(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from cybox objects in each container
          (grouped by observation index and root cybox object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().

        It's okay if the operands are of different type and comparison is
        not supported: they will compare unequal.  (Note: this would include
        things like pairs of dicts and lists which have the same contents...
        should verify what to do here.)
        """

        # Figure out what literal value was given in the pattern
        literal_node = ctx.primitiveLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        debug_label = "exitPropTestEqual ({} {})".format(
            ctx.getChild(1).getText(),
            literal_value
        )

        obs_values = self.__pop(debug_label)

        def equality_pred(value):
            result = False
            eq_func = _get_table_symmetric(_COMPARE_EQ_FUNCS,
                                           type(literal_value),
                                           type(value))
            if eq_func is not None:
                result = eq_func(value, literal_value)

            if ctx.NEQ():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, equality_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestOrder(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from cybox objects in each container
          (grouped by observation index and root cybox object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().

        If operand types are not supported for order-comparison, current
        spec says the result must be False.  But this means that for two
        values for which comparison is not supported, both a < b and
        a >= b would be false.  That's certainly not normal semantics for
        these operators...
        """
        # Figure out what literal value was given in the pattern
        literal_node = ctx.orderableLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_str = ctx.getChild(1).getText()
        debug_label = "exitPropTestOrder ('{}' {})".format(
            op_str,
            literal_value
        )

        obs_values = self.__pop(debug_label)

        def order_pred(value):
            cmp_func = _get_table_symmetric(_COMPARE_ORDER_FUNCS,
                                            type(literal_value),
                                            type(value))

            if cmp_func is None:
                return False
                # raise TypeMismatchException(op_str,
                #     type(value),
                #     literal_terminal.getSymbol().type)

            result = cmp_func(value, literal_value)

            if ctx.LT():
                result = result < 0
            elif ctx.GT():
                result = result > 0
            elif ctx.LE():
                result = result <= 0
            elif ctx.GE():
                result = result >= 0
            else:
                # shouldn't ever happen, right?
                raise UnsupportedOperatorError(op_str)

            return result

        passed_obs = _obs_map_prop_test(obs_values, order_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestSet(self, ctx):
        """
        Consumes (1) a set object from exitSetLiteral(), and (2) an observation
           data map, {obs_id: {...}, ...}, representing selected values from
           cybox objects in each container (grouped by observation index and
           root cybox object ID).  See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().
        """

        debug_label = "exitPropTestSet{}".format(
            " (not)" if ctx.NOT() else ""
        )
        s = self.__pop(debug_label)  # pop the set
        obs_values = self.__pop(debug_label)  # pop the observation values

        def set_pred(value):
            result = False
            try:
                result = value in s
            except TypeError:
                # Ignore errors about un-hashability.  Not all values
                # selected from a cybox object are hashable (e.g.
                # lists and dicts).  Those obviously can't be in the
                # given set!
                pass

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, set_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestLike(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from cybox objects in each container
          (grouped by observation index and root cybox object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """

        operand_str = _literal_terminal_to_python_val(ctx.StringLiteral())
        debug_label = "exitPropTestLike ({}{})".format(
            "not " if ctx.NOT() else "",
            operand_str
        )

        obs_values = self.__pop(debug_label)

        regex = _like_to_regex(operand_str)
        # compile and cache this to improve performance
        compiled_re = re.compile(regex)

        def like_pred(value):
            # non-strings can't match
            if not isinstance(value, six.string_types):
                return False

            result = compiled_re.match(value)
            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, like_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestRegex(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from cybox objects in each container
          (grouped by observation index and root cybox object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """

        regex_terminal = ctx.RegexLiteral()
        debug_label = "exitPropTestRegex ({}{})".format(
            "not " if ctx.NOT() else "",
            regex_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        regex = regex_terminal.getText()[1:-1]  # strip "quotes"
        compiled_re = re.compile(regex)

        def regex_pred(value):
            if not isinstance(value, six.string_types):
                return False

            # Don't need a full-string match
            result = compiled_re.search(value)
            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, regex_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestInSubnet(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from cybox objects in each container
          (grouped by observation index and root cybox object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """
        subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = "exitPropTestInSubnet ({}{})".format(
            "not " if ctx.NOT() else "",
            subnet_str
        )
        obs_values = self.__pop(debug_label)

        def subnet_pred(value):
            if not isinstance(value, six.string_types):
                return False

            result = _ip_or_cidr_in_subnet(value, subnet_str)
            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, subnet_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestContains(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from cybox objects in each container
          (grouped by observation index and root cybox object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          cybox object values which pass the test, each with an associated
          set of root cybox object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """
        ip_or_subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = "exitPropTestContains ({}{})".format(
            "not " if ctx.NOT() else "",
            ip_or_subnet_str
        )
        obs_values = self.__pop(debug_label)

        def contains_pred(value):
            if not isinstance(value, six.string_types):
                return False

            result = _ip_or_cidr_in_subnet(ip_or_subnet_str, value)
            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, contains_pred)

        self.__push(passed_obs, debug_label)

    def exitObjectPath(self, ctx):
        """
        Consumes nothing from the stack
        Produces a mapping:
            {
              observation-idx: {
                  "cybox_obj_id1": [value, value, ...],
                  "cybox_obj_id2": [value, value, ...],
              },
              etc...
            }
          which are the values selected by the path, organized according to
          the the observations they belong to, and the "root" cybox objects
          which began a chain of dereferences (if any).  These will be used in
          subsequent comparisons to select some of the observations.
          I use observations' indices into the self.__observations list as
          identifiers.

        So this (and descendant rules) is where (the main) stack values come
        into being.
        """

        # We don't actually need to do any post-processing to the top stack
        # value.  But I keep this function here for the sake of documentation.
        pass

    def exitObjectType(self, ctx):
        """
        Consumes nothing from the stack.
        Produces a map, {observation-idx: {...}, ...}, representing those
        cybox objects with the given type.  See exitObjectPath().
        """
        type_ = ctx.Identifier().getText()
        results = {}
        for obs_idx, obs in enumerate(self.__observations):

            # Skip observations without objects
            if "objects" not in obs:
                continue

            objects_from_this_obs = {}
            for obj_id, obj in six.iteritems(obs["objects"]):
                if "type" in obj and obj["type"] == type_:
                    objects_from_this_obs[obj_id] = [obj]

            if len(objects_from_this_obs) > 0:
                results[obs_idx] = objects_from_this_obs

        self.__push(results, "exitObjectType ({})".format(type_))

    def __dereference_objects(self, prop_name, obs_map):
        """
        If prop_name is a reference property, this "dereferences" it,
        substituting the referenced cybox object for the reference.  Reference
        properties end in "_ref" or "_refs".  The former must have a string
        value, the latter must be a list of strings.  Any references which
        don't resolve are dropped and don't produce an error.  The references
        are resolved only against the cybox objects in the same container as
        the reference.

        If the property isn't a reference, this method does nothing.

        :param prop_name: The property which was just stepped, i.e. the "key"
            in a key path step.
        :param obs_map: The observation data after stepping, but before it
            has been pushed onto the stack.  This method acts as an additional
            "processing" step on that data.
        :return: If prop_name is not a reference property, obs_map is
            returned unchanged.  If it is a reference property, the
            dereferenced observation data is returned.
        """

        if prop_name.endswith("_ref"):
            # An object reference.  All top-level values should be
            # string cybox object IDs.
            dereferenced_obs_map = {}
            for obs_idx, cybox_obj_map in six.iteritems(obs_map):
                dereferenced_cybox_obj_map = {}
                for cybox_obj_id, references in six.iteritems(cybox_obj_map):
                    dereferenced_cybox_objs = _dereference_cybox_objs(
                        # Note that "objects" must be a key of the observation,
                        # or it wouldn't be on the stack.  See exitObjectType().
                        self.__observations[obs_idx]["objects"],
                        references,
                        prop_name
                    )

                    if len(dereferenced_cybox_objs) > 0:
                        dereferenced_cybox_obj_map[cybox_obj_id] = \
                            dereferenced_cybox_objs

                if len(dereferenced_cybox_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cybox_obj_map

            obs_map = dereferenced_obs_map

        elif prop_name.endswith("_refs"):
            # A list of object references.  All top-level values should
            # be lists (of cybox object references).
            dereferenced_obs_map = {}
            for obs_idx, cybox_obj_map in six.iteritems(obs_map):
                dereferenced_cybox_obj_map = {}
                for cybox_obj_id, reference_lists in six.iteritems(cybox_obj_map):
                    dereferenced_cybox_obj_lists = []
                    for reference_list in reference_lists:
                        if not isinstance(reference_list, list):
                            raise MatcherException(
                                "The value of reference list property '{}' was not "
                                "a list!  Got {}".format(
                                    prop_name, reference_list
                                ))

                        dereferenced_cybox_objs = _dereference_cybox_objs(
                            self.__observations[obs_idx]["objects"],
                            reference_list,
                            prop_name
                        )

                        if len(dereferenced_cybox_objs) > 0:
                            dereferenced_cybox_obj_lists.append(
                                dereferenced_cybox_objs)

                    if len(dereferenced_cybox_obj_lists) > 0:
                        dereferenced_cybox_obj_map[cybox_obj_id] = \
                            dereferenced_cybox_obj_lists

                if len(dereferenced_cybox_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cybox_obj_map

            obs_map = dereferenced_obs_map

        return obs_map

    def exitFirstPathComponent(self, ctx):
        """
        Consumes the results of exitObjectType.
        Produces a similar structure, but with cybox objects which
          don't have the given property, filtered out.  For those which
          do have the property, the property value is substituted for
          the object.  If the property was a reference, a second substitution
          occurs: the referent is substituted in place of the reference (if
          the reference resolves).  This enables subsequent path steps to step
          into the referenced cybox object(s).

          If all cybox objects from a container are filtered out, the
          container is dropped.
        """

        prop_name = ctx.Identifier().getText()
        debug_label = "exitFirstPathComponent ({})".format(prop_name)
        obs_val = self.__pop(debug_label)

        filtered_obs_map = _step_filter_observations(obs_val, prop_name)
        dereferenced_obs_map = self.__dereference_objects(prop_name,
                                                          filtered_obs_map)

        self.__push(dereferenced_obs_map, debug_label)

    def exitKeyPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent().
        """
        prop_name = ctx.Identifier().getText()
        debug_label = "exitKeyPathStep ({})".format(prop_name)
        obs_val = self.__pop(debug_label)

        filtered_obs_map = _step_filter_observations(obs_val, prop_name)
        dereferenced_obs_map = self.__dereference_objects(prop_name,
                                                          filtered_obs_map)

        self.__push(dereferenced_obs_map, debug_label)

    def exitIndexPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent(), but takes a list index
        step.
        """
        if ctx.IntLiteral():
            index = _literal_terminal_to_python_val(ctx.IntLiteral())
            if index < 0:
                raise MatcherException("Invalid list index: {}".format(index))
            debug_label = "exitIndexPathStep ({})".format(index)
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations(obs_val, index)

        elif ctx.ASTERISK():
            # In this case, we step into all of the list elements.
            debug_label = "exitIndexPathStep (*)"
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations_index_star(obs_val)

        else:
            # reallly shouldn't happen...
            raise MatcherInternalError("Unsupported index path step!")

        self.__push(filtered_obs_map, debug_label)

    def exitSetLiteral(self, ctx):
        """
        Consumes nothing
        Produces a python set object with values from the set literal
        """

        literal_nodes = ctx.primitiveLiteral()

        # make a python set from the set literal.
        s = set()
        for literal_node in literal_nodes:
            literal_terminal = _get_first_terminal_descendant(literal_node)
            literal_value = _literal_terminal_to_python_val(literal_terminal)
            s.add(literal_value)

        self.__push(s, "exitSetLiteral ({})".format(ctx.getText()))


def match(pattern, containers, timestamps, verbose=False):
    """
    Match the given pattern against the given containers and timestamps.

    :param pattern: The cybox pattern
    :param containers: A list of cybox containers, as a list of dicts.  CybOX
        json should be parsed into native python structures before calling
        this function.
    :param timestamps: A list of timestamps corresponding to the containers,
        as a list of timezone-aware datetime.datetime objects.  There must be
        the same number of timestamps as containers.
    :param verbose: Whether to dump detailed info about matcher operation
    :return: True if the pattern matches, False if not
    """

    in_ = antlr4.InputStream(pattern)
    lexer = CyboxPatternLexer(in_)
    lexer.removeErrorListeners()  # remove the default "console" listener
    token_stream = antlr4.CommonTokenStream(lexer)

    parser = CyboxPatternParser(token_stream)
    parser.removeErrorListeners()  # remove the default "console" listener
    error_listener = MatcherErrorListener()
    parser.addErrorListener(error_listener)

    # I found no public API for this...
    # The default error handler tries to keep parsing, and I don't
    # think that's appropriate here.  (These error handlers are only for
    # handling the built-in RecognitionException errors.)
    parser._errHandler = antlr4.BailErrorStrategy()

    # parser.setTrace(True)

    matcher = MatchListener(containers, timestamps, verbose)
    matched = False
    try:
        tree = parser.pattern()
        # print(tree.toStringTree(recog=parser))

        antlr4.ParseTreeWalker.DEFAULT.walk(matcher, tree)

        matched = matcher.matched()

    except antlr4.error.Errors.ParseCancellationException as e:
        # The cancellation exception wraps the real RecognitionException which
        # caused the parser to bail.
        real_exc = e.args[0]

        # I want to bail when the first error is hit.  But I also want
        # a decent error message.  When an error is encountered in
        # Parser.match(), the BailErrorStrategy produces the
        # ParseCancellationException.  It is not a subclass of
        # RecognitionException, so none of the 'except' clauses which would
        # normally report an error are invoked.
        #
        # Error message creation is buried in the ErrorStrategy, and I can
        # (ab)use the API to get a message: register an error listener with
        # the parser, force an error report, then get the message out of the
        # listener.  Error listener registration is above; now we force its
        # invocation.  Wish this could be cleaner...
        parser._errHandler.reportError(parser, real_exc)

        # should probably chain exceptions if we can...
        # Should I report the cancellation or recognition exception as the
        # cause...?
        six.raise_from(MatcherException(error_listener.error_message),
                       real_exc)

    return matched


def main():
    """
    Can be used as a command line tool to test pattern-matcher.
    """

    arg_parser = argparse.ArgumentParser(description="Match CybOX patterns to CybOX containers")
    arg_parser.add_argument("-p", "--patterns", required=True,
                            type=argparse.FileType("r"), help="""
    Specify a file containing CybOX patterns, one per line.
    """)
    arg_parser.add_argument("-f", "--file", required=True,
                            type=argparse.FileType("r"), help="""
    A file containing JSON list of cybox containers to match against.
    """)
    arg_parser.add_argument("-t", "--timestamps", type=argparse.FileType("r"),
                            help="""
                            Specify a file with ISO-formatted timestamps, one
                            per line.  If given, this must have at least as many
                            timestamps as there are containers (extras will be
                            ignored).  If not given, all containers will be
                            assigned the current time.
                            """)
    arg_parser.add_argument("-v", "--verbose", action="store_true",
                            help="""Be verbose""")

    args = arg_parser.parse_args()
    json_in = args.file
    try:
        containers = json.load(json_in)
    finally:
        json_in.close()

    if args.timestamps:
        try:
            timestamps = []
            for line in args.timestamps:
                line = line.strip()
                if not line:
                    continue  # skip blank lines
                timestamp = _str_to_datetime(line)
                if timestamp is None:
                    raise ValueError("Invalid timestamp format: {}".format(line))
                timestamps.append(timestamp)
        finally:
            args.timestamps.close()
    else:
        timestamps = [datetime.datetime.now(dateutil.tz.tzutc())
                      for _ in containers]

    if len(timestamps) < len(containers):
        print("There are fewer timestamps than containers! ({}<{})".format(
            len(timestamps), len(containers)
        ))
        sys.exit(1)
    elif len(timestamps) > len(containers):
        timestamps = timestamps[:len(containers)]

    try:
        for pattern in args.patterns:
            pattern = pattern.strip()
            if not pattern:
                continue  # skip blank lines
            if pattern[0] == "#":
                continue  # skip commented out lines
            if match(pattern, containers, timestamps, args.verbose):
                print("\nPASS: ", pattern)
            else:
                print("\nFAIL: ", pattern)
    finally:
        args.patterns.close()


if __name__ == '__main__':
    main()
