"""Deterministic computation over earlier results (`dojo.compute.table`).

A drafted program reads data with tools and turns it into values with the
quarantined extractor. Picking among records ("the highest-rated hotel, the
cheaper one on a tie", "the total of March's payments") asked that model to
compare whole tables in one reply, which it often got wrong. This step does the
comparison as a fixed function instead:

    inputs   input1..input4: owner-signed edges to earlier steps' results (a
             tool result's whole JSON text, or an extracted/computed value)
    filter1..filter3   "<ref> <op> <operand>"   every filter must hold
    order1, order2     "max <ref>" | "min <ref>" (numeric; ties fall through,
                       then the key in ascending order)
    output             "key" | "keys [n]" | "count" | "sum <ref>" | "value <ref>"
                       | "values <ref>" | "pairs <ref>" | "mode <ref>" | "mode *.<field>"

    ref      "key" | N | "N.field" | "field"   (N names inputN, 1..4; a bare
             field is a field of input1's records, i.e. "1.field")
    op       contains | lacks | startswith | is | isnt | = | > | >= | < | <=

"mode" is the most frequent value (ties: the first in alphabetical order);
"mode *.<field>" counts that field over the records of ALL inputs together
(e.g. the senders of messages read from several channels), with no filter or
order.

Where the run allows it (`calc=True`), the output may also be
"calc <expression>", with no filter or order: exact decimal arithmetic on the
first number in each input, written #1..#4, with numbers, + - * / ( ) and
min(a, b, ...), max(a, b, ...), rounded to 2 decimal places. An input with no
number, a division by zero or a value beyond CALC_LIMIT gives an empty output:
nothing is guessed. Which numbers an expression may use is the owner's
review's rule (`calc_constants`), not this function's.

input1 gives the rows: an object's entries (key -> value), a list of records
(key = its "id", "id_", "name", "title" or "filename", else its position), a list of texts, or a
text (lines, or items separated by "; "). Every other input is an object or
list joined to those rows by key. A ref's number is the first decimal number
in its text ("Rating: 4.2" -> 4.2).

The function is pure and total over its inputs: the same signed inputs always
give the same output, no data can choose an operation, a tool or a field, and
nothing leaves the connector. Its output is data exactly like an extraction's
(`{"text": ..., "items": [...]}`), so the owner's review keeps every rule for
it: never a destination, reaching a later field only through a signed edge.

The trusted executor computes the same function in Rust
(`crates/savana-table-compute`), byte for byte
(`tests/test_compute_rust_parity.py`). Where Python's result rested on
interpreter internals, or raised, this module states the rule instead:

* JSON (`_json`): a text nested more than MAX_JSON_DEPTH arrays/objects deep
  (where `json.loads` would hit the recursion limit), one using the
  constants NaN, Infinity or -Infinity, or one whose strings hold a lone
  surrogate escape is plain text, as is (by Python's default
  `int_max_str_digits`) an integer literal of more than 4300 digits.
* Numbers: an int beyond the float range counts as infinite (`_float`), and
  an infinite number has no text (`_format`), so a sum past the float range
  is the empty item "".
* Folding (`_fold`) is NFKC then `str.lower()` (full lowercase, final
  sigma), not `casefold()`; "keys N" takes ASCII digits.
* "calc" runs in an explicit decimal context (`_CALC_CONTEXT`: precision 34,
  ROUND_HALF_EVEN, unbounded exponents), and `calc_constants` of any other
  output is empty.
"""
import decimal
import json
import math
import re
import unicodedata

COMPUTE_TOOL = "dojo.compute.table"
COMPUTE_UPSTREAM = "savana_compute_table"
INPUT_FIELDS = ("input1", "input2", "input3", "input4")
FILTER_FIELDS = ("filter1", "filter2", "filter3")
ORDER_FIELDS = ("order1", "order2")
OUTPUT_FIELD = "output"
SPEC_FIELDS = (*FILTER_FIELDS, *ORDER_FIELDS, OUTPUT_FIELD)
FIELDS = (*INPUT_FIELDS, *SPEC_FIELDS)
FILTER_OPS = ("contains", "lacks", "startswith", "is", "isnt", "=", ">", ">=", "<", "<=")
OUTPUTS = ("key", "keys", "count", "sum", "value", "values", "pairs", "mode")
MAX_SPEC_BYTES = 128
MAX_OPERAND_BYTES = 96
MAX_ROWS = 256
MAX_ITEMS = 32
MAX_ITEM_BYTES = 160
MAX_TEXT_BYTES = 480
SEPARATOR = "; "
_REF = re.compile(r"^(?:key|[1-4](?:\.[A-Za-z_][A-Za-z0-9_]{0,31})?)$")
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
_NUMBER = re.compile(r"-?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?")
_LABEL = re.compile(r"^[A-Za-z][A-Za-z ]{0,39}:\s*(\S.*)$")
CALC = "calc"
CALC_LIMIT = decimal.Decimal("1e12")
MAX_CALC_TOKENS = 64
MAX_CALC_DEPTH = 8
_CALC_TOKEN = re.compile(r"\s*(?:(?P<number>[0-9]+(?:\.[0-9]+)?)|(?P<ref>#[1-4])|(?P<function>min|max)"
                         r"|(?P<symbol>[-+*/(),]))")
_CENT = decimal.Decimal("0.01")
# Exponents unbounded, so a value never overflows or underflows: rounding to
# 34 significant digits is the only inexact step.
_CALC_CONTEXT = decimal.Context(prec=34, rounding=decimal.ROUND_HALF_EVEN,
                                Emax=decimal.MAX_EMAX, Emin=decimal.MIN_EMIN)
MAX_JSON_DEPTH = 128
_JSON_SCAN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"?|[][{}]', re.S)
_SURROGATE = re.compile("[\ud800-\udfff]")
_NOT_JSON = object()


class ComputeSpecError(ValueError):
    """A filter, order or output text outside the grammar."""


def _spec_text(text):
    if (type(text) is not str or not text or text != text.strip() or len(text.encode()) > MAX_SPEC_BYTES
            or any(ord(ch) < 32 for ch in text)):
        raise ComputeSpecError("compute_spec")
    return text


def _ref(text, inputs):
    if text != "key" and _FIELD.match(text):
        text = "1." + text  # a bare field: of input1's records
    if not _REF.match(text):
        raise ComputeSpecError("compute_spec")
    if text != "key" and int(text[0]) > inputs:
        raise ComputeSpecError("compute_input")
    return text


def parse_filter(text, inputs=4):
    """'<ref> <op> <operand>' -> (ref, op, operand)."""
    parts = _spec_text(text).split(" ", 2)
    if len(parts) != 3 or parts[1] not in FILTER_OPS or not parts[2].strip():
        raise ComputeSpecError("compute_spec")
    operand = parts[2].strip()
    if len(operand.encode()) > MAX_OPERAND_BYTES:
        raise ComputeSpecError("compute_spec")
    if parts[1] in ("=", ">", ">=", "<", "<=") and _number(operand) is None:
        raise ComputeSpecError("compute_spec")
    return _ref(parts[0], inputs), parts[1], operand


def parse_order(text, inputs=4):
    """'max <ref>' | 'min <ref>' -> (direction, ref)."""
    parts = _spec_text(text).split(" ")
    if len(parts) != 2 or parts[0] not in ("max", "min"):
        raise ComputeSpecError("compute_spec")
    return parts[0], _ref(parts[1], inputs)


def _calc_tokens(text):
    tokens, at = [], 0
    while at < len(text):
        match = _CALC_TOKEN.match(text, at)
        if match is None or match.end() == at:
            raise ComputeSpecError("compute_spec")
        at = match.end()
        tokens.append((match.lastgroup, match.group(match.lastgroup)))
        if len(tokens) > MAX_CALC_TOKENS:
            raise ComputeSpecError("compute_spec")
    return tokens


def parse_calc(text, inputs=4):
    """An expression -> its tree: ("number", Decimal) | ("ref", n) |
    ("neg", tree) | (op, tree, tree) for + - * / | ("min" | "max", [tree, ...])."""
    tokens = _calc_tokens(text)
    at = 0

    def peek():
        return tokens[at][1] if at < len(tokens) else None

    def take(symbol=None):
        nonlocal at
        if at == len(tokens) or (symbol is not None and tokens[at][1] != symbol):
            raise ComputeSpecError("compute_spec")
        at += 1
        return tokens[at - 1]

    def expression(depth):
        if depth > MAX_CALC_DEPTH:
            raise ComputeSpecError("compute_spec")
        tree = term(depth)
        while peek() in ("+", "-"):
            tree = (take()[1], tree, term(depth))
        return tree

    def term(depth):
        tree = unary(depth)
        while peek() in ("*", "/"):
            tree = (take()[1], tree, unary(depth))
        return tree

    def unary(depth):
        if peek() == "-":
            take()
            if depth + 1 > MAX_CALC_DEPTH:
                raise ComputeSpecError("compute_spec")
            return ("neg", unary(depth + 1))
        return atom(depth)

    def atom(depth):
        kind, value = take()
        if kind == "number":
            return ("number", decimal.Decimal(value))
        if kind == "ref":
            if int(value[1]) > inputs:
                raise ComputeSpecError("compute_input")
            return ("ref", int(value[1]))
        if kind == "function":
            take("(")
            arguments = [expression(depth + 1)]
            while peek() == ",":
                take()
                arguments.append(expression(depth + 1))
            take(")")
            if len(arguments) < 2:
                raise ComputeSpecError("compute_spec")
            return (value, arguments)
        if value == "(":
            tree = expression(depth + 1)
            take(")")
            return tree
        raise ComputeSpecError("compute_spec")

    tree = expression(0)
    if at != len(tokens):
        raise ComputeSpecError("compute_spec")
    return tree


def calc_constants(output, inputs=4):
    """The numbers a "calc" output writes itself, for the owner's review
    (none for any other output)."""
    found = set()

    def walk(tree):
        if tree[0] == "number":
            found.add(tree[1])
        elif tree[0] in ("min", "max"):
            for argument in tree[1]:
                walk(argument)
        elif tree[0] == "neg":
            walk(tree[1])
        elif tree[0] != "ref":
            walk(tree[1])
            walk(tree[2])
    kind, tree, _limit = parse_output(output, inputs, calc=True)
    if kind == CALC:
        walk(tree)
    return found


def parse_output(text, inputs=4, calc=False):
    """-> (kind, ref or None, limit or None); for "calc", (kind, tree, None)."""
    parts = _spec_text(text).split(" ")
    kind = parts[0]
    if kind == CALC and calc:
        if len(parts) < 2:
            raise ComputeSpecError("compute_spec")
        return kind, parse_calc(text[len(CALC) + 1:], inputs), None
    if kind not in OUTPUTS:
        raise ComputeSpecError("compute_spec")
    if kind in ("key", "count"):
        if len(parts) != 1:
            raise ComputeSpecError("compute_spec")
        return kind, None, None
    if kind == "keys":
        if len(parts) == 1:
            return kind, None, None
        if (len(parts) != 2 or not (parts[1].isascii() and parts[1].isdigit())
                or not 1 <= int(parts[1]) <= MAX_ITEMS):
            raise ComputeSpecError("compute_spec")
        return kind, None, int(parts[1])
    if len(parts) != 2:
        raise ComputeSpecError("compute_spec")
    if kind == "mode" and parts[1].startswith("*."):
        if not _FIELD.match(parts[1][2:]):
            raise ComputeSpecError("compute_spec")
        return kind, parts[1], None
    return kind, _ref(parts[1], inputs), None


def _fold(text):
    return unicodedata.normalize("NFKC", text).lower().strip()


def _float(value):
    """float(value), where an int beyond the float range is infinite (as
    float() of its digits is) rather than an error."""
    try:
        return float(value)
    except OverflowError:
        return math.inf if value > 0 else -math.inf


def _number(value):
    if type(value) is bool or value is None:
        return None
    if type(value) in (int, float):
        return _float(value)
    if type(value) is not str:
        return None
    match = _NUMBER.search(value)
    return None if match is None else float(match.group(0).replace(",", ""))


def _text(value):
    if value is None:
        return None
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) in (int, float):
        return _format(_float(value))
    if type(value) is list:
        return SEPARATOR.join(t for t in (_text(v) for v in value) if t)
    if type(value) is dict:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _format(number):
    if not math.isfinite(number):
        return ""  # a number past the float range has no text
    if number == int(number) and abs(number) < 1e15:
        return str(int(number))
    return f"{number:.2f}".rstrip("0").rstrip(".")


def _not_json(_constant):
    raise ValueError("compute_json_constant")


def _json(text):
    """`text` as JSON, or _NOT_JSON where it is plain text: not JSON, nested
    more than MAX_JSON_DEPTH deep, using NaN/Infinity, or holding a lone
    surrogate escape."""
    if text.count("[") + text.count("{") > MAX_JSON_DEPTH:
        depth = 0
        for token in _JSON_SCAN.finditer(text):
            mark = token.group(0)
            if mark in ("[", "{"):
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    return _NOT_JSON
            elif mark in ("]", "}"):
                depth -= 1
    try:
        value = json.loads(text, parse_constant=_not_json)
    except ValueError:
        return _NOT_JSON
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            if _SURROGATE.search(item):
                return _NOT_JSON
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is dict:
            pending.extend(item)
            pending.extend(item.values())
    return value


def _record_key(record, index):
    for name in ("id", "id_", "name", "title", "filename"):
        if name in record and _text(record[name]):
            return _text(record[name])
    return str(index + 1)


def table(text):
    """One input's text -> ordered [(key, value)] rows (at most MAX_ROWS)."""
    value = _json(text)
    if value is _NOT_JSON:
        value = text
    rows = []
    if type(value) is dict:
        rows = [(str(k), v) for k, v in value.items()]
    elif type(value) is list:
        for index, item in enumerate(value):
            rows.append((_record_key(item, index), item) if type(item) is dict else (_text(item) or "", item))
    elif type(value) is str:
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        if len(lines) == 1 and SEPARATOR.strip() in lines[0]:
            lines = [item.strip() for item in lines[0].split(SEPARATOR.strip()) if item.strip()]
        elif len(lines) > 1:
            # "Hotel Names: A\nB\nC" lists A, B and C.
            label = _LABEL.match(lines[0])
            if label and not any(ch.isdigit() for ch in lines[0][:lines[0].index(":")]):
                lines[0] = label.group(1).strip()
        rows = [(line, line) for line in lines]
    elif value is not None:
        rows = [(_text(value), value)]
    return [(k, v) for k, v in rows if k][:MAX_ROWS]


def _lookup(rows):
    exact = {}
    folded = {}
    for key, value in rows:
        exact.setdefault(key, value)
        folded.setdefault(_fold(key), value)
    return exact, folded


def _resolve(ref, key, columns):
    if ref == "key":
        return key
    column = columns[int(ref[0]) - 1]
    if "." not in ref:
        return column
    return column.get(ref.split(".", 1)[1]) if type(column) is dict else None


def _holds(value, op, operand):
    if op in ("=", ">", ">=", "<", "<="):
        number, bound = _number(value), _number(operand)
        if number is None:
            return False
        return {"=": number == bound, ">": number > bound, ">=": number >= bound,
                "<": number < bound, "<=": number <= bound}[op]
    text = _text(value)
    if text is None:
        return False
    text, needle = _fold(text), _fold(operand)
    return {"contains": needle in text, "lacks": needle not in text, "startswith": text.startswith(needle),
            "is": text == needle, "isnt": text != needle}[op]


def _bounded(items):
    items = [" ".join(i.split()).encode()[:MAX_ITEM_BYTES].decode("utf-8", "ignore") for i in items][:MAX_ITEMS]
    kept, size = [], 0
    for item in items:
        size += len(item.encode()) + (len(SEPARATOR) if kept else 0)
        if size > MAX_TEXT_BYTES:
            break
        kept.append(item)
    return {"text": SEPARATOR.join(kept), "items": kept}


def _calc_value(text):
    """The first number in one input, exactly: an extraction's or a
    computation's value ({"text": ...}), a JSON number, or plain text."""
    value = _json(text)
    if value is _NOT_JSON:
        value = text
    if type(value) is dict:
        value = value.get("text")
    if type(value) in (int, float) and type(value) is not bool:
        number = decimal.Decimal(repr(value))
        return number if number.is_finite() and abs(number) <= CALC_LIMIT else None
    if type(value) is not str:
        return None
    match = _NUMBER.search(value)
    if match is None:
        return None
    number = decimal.Decimal(match.group(0).replace(",", ""))
    return number if abs(number) <= CALC_LIMIT else None


def _calc_eval(tree, values):
    """The tree's value over the inputs' numbers, or None when an input has
    none, a divisor is zero or a value leaves [-CALC_LIMIT, CALC_LIMIT]."""
    kind = tree[0]
    if kind == "number":
        result = tree[1]
    elif kind == "ref":
        result = values[tree[1] - 1]
    elif kind == "neg":
        result = _calc_eval(tree[1], values)
        result = None if result is None else -result
    elif kind in ("min", "max"):
        found = [_calc_eval(argument, values) for argument in tree[1]]
        result = None if None in found else (min(found) if kind == "min" else max(found))
    else:
        left, right = _calc_eval(tree[1], values), _calc_eval(tree[2], values)
        if left is None or right is None or (kind == "/" and right == 0):
            return None
        result = (left + right if kind == "+" else left - right if kind == "-"
                  else left * right if kind == "*" else left / right)
    return None if result is None or abs(result) > CALC_LIMIT else result


def _calc_format(value):
    value = value.quantize(_CENT, rounding=decimal.ROUND_HALF_EVEN)
    if value == value.to_integral_value():
        return str(int(value))
    return format(value, "f").rstrip("0").rstrip(".")


def _mode(values):
    """The most frequent non-empty value; ties go to the alphabetically first."""
    counts = {}
    for value in values:
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return {"text": "", "items": []}
    best = max(counts.values())
    return _bounded([min(value for value, n in counts.items() if n == best)])


def compute(inputs, filters=(), orders=(), output="key", calc=False):
    """The step's whole function: input texts (input1 first; "" = absent) and
    spec texts -> {"text": ..., "items": [...]}. Raises only on a malformed spec
    (which the owner's review already refused). `calc` allows a "calc" output."""
    count = next((i for i, text in enumerate(inputs) if text == ""), len(inputs))
    if count == 0 or any(text != "" for text in inputs[count:]):
        raise ComputeSpecError("compute_input")
    present = list(inputs[:count])
    filters = [parse_filter(f, count) for f in filters if f]
    orders = [parse_order(o, count) for o in orders if o]
    kind, ref, limit = parse_output(output, count, calc)
    if kind == CALC:
        # Arithmetic on one number per input: rows, filters and orders do not apply.
        if filters or orders:
            raise ComputeSpecError("compute_spec")
        with decimal.localcontext(_CALC_CONTEXT):
            result = _calc_eval(ref, [_calc_value(text) for text in present])
        return {"text": "", "items": []} if result is None else _bounded([_calc_format(result)])
    if kind == "mode" and ref.startswith("*."):
        # One field over the records of every input together.
        if filters or orders:
            raise ComputeSpecError("compute_spec")
        return _mode(_text(value.get(ref[2:])) for text in present for _key, value in table(text)
                     if type(value) is dict)
    base = table(present[0])
    joins = [_lookup(table(text)) for text in present[1:]]
    rows = []
    for key, value in base:
        columns = [value]
        for exact, folded in joins:
            columns.append(exact[key] if key in exact else folded.get(_fold(key)))
        rows.append((key, columns))
    rows = [r for r in rows if all(_holds(_resolve(fr, r[0], r[1]), op, operand) for fr, op, operand in filters)]
    rows.sort(key=lambda r: r[0])
    for direction, oref in reversed(orders):
        # Missing numbers sort last in either direction.
        present_rows = [r for r in rows if _number(_resolve(oref, r[0], r[1])) is not None]
        missing = [r for r in rows if _number(_resolve(oref, r[0], r[1])) is None]
        present_rows.sort(key=lambda r: _number(_resolve(oref, r[0], r[1])), reverse=direction == "max")
        rows = present_rows + missing
    if kind == "count":
        return _bounded([str(len(rows))])
    if kind == "sum":
        numbers = [_number(_resolve(ref, k, c)) for k, c in rows]
        return _bounded([_format(sum(n for n in numbers if n is not None))])
    if not rows:
        return {"text": "", "items": []}
    if kind == "key":
        return _bounded([rows[0][0]])
    if kind == "keys":
        return _bounded([k for k, _c in rows][:limit])
    if kind == "value":
        return _bounded([_text(_resolve(ref, rows[0][0], rows[0][1])) or ""])
    if kind == "values":
        return _bounded([t for t in (_text(_resolve(ref, k, c)) for k, c in rows) if t])
    if kind == "mode":
        return _mode(_text(_resolve(ref, k, c)) for k, c in rows)
    return _bounded([f"{k}: {_text(_resolve(ref, k, c)) or ''}" for k, c in rows])


def validate_spec(args, inputs, calc=False):
    """The owner's review of one step's spec texts -> {field: text} (absent
    fields as ""). Raises ComputeSpecError. `calc` allows a "calc" output
    (whose numbers the review checks separately, `calc_constants`)."""
    values = {}
    for name in SPEC_FIELDS:
        raw = args.get(name)
        if raw is None:
            if name == OUTPUT_FIELD:
                raise ComputeSpecError("compute_spec")
            values[name] = ""
            continue
        text = raw["text"] if type(raw) is dict and set(raw) == {"text"} else raw
        if name in FILTER_FIELDS:
            parse_filter(text, inputs)
        elif name in ORDER_FIELDS:
            parse_order(text, inputs)
        else:
            parse_output(text, inputs, calc)
        values[name] = text
    if (values[OUTPUT_FIELD].startswith(("mode *.", CALC + " "))
            and any(values[name] for name in (*FILTER_FIELDS, *ORDER_FIELDS))):
        raise ComputeSpecError("compute_spec")
    return values
