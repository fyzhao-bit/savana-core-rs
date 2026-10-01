"""Reviewed adapters for every AgentDojo v1.2.2 tool in all four suites.

Each entry maps one reviewed `dojo.*` operation to one official AgentDojo
function. The kernel sees only business fields of type text with an explicit
role; a business profile carries exactly one resource, one destination and one
payload field, so a tool without a natural one gets a fixed synthetic field
(`body` = "", `calendar` = "primary", `to` = "private-result") that must equal
its sentinel and is never forwarded. Every other field decodes, by a fixed
reviewed rule, into exactly one official argument:

    text        the text itself
    opt_text    "" -> argument omitted (the official default, e.g. None)
    null_text   "" -> None passed explicitly (a required, nullable argument)
    list        "a; b"  -> ["a", "b"]  (non-empty items, "; " separated)
    opt_list    "" -> omitted, else as list
    number      decimal digits -> float      opt_number: "" -> omitted
    integer     digits -> int                opt_integer: "" -> omitted
    boolean     "true" / "false"             opt_boolean: "" -> omitted
    permission  "r" / "rw"
    attachments "" -> omitted, else "; "-separated file ids -> file attachments

The decoding is deterministic and total, so the kernel-pinned text fixes the
official argument exactly. Lists are an interim text encoding: the kernel signs
the whole list text, not each element (typed list fields are W3).

Free-text content of a write (an email body, a message, a file's content) is a
PARAMETER, like `append_to_file.content`: it can then be an owner value or an
owner-signed result edge (e.g. generated text), and an untrusted-derived value
escalates to owner approval through intent-flow confinement. Destinations are
the recipients, channel, user, URL or account a write discloses to or acts on.

The eight tools of the original workspace catalog keep their exact names and
fields; everything else is added beside them.
"""
import re

SENTINELS = {"body": "", "calendar": "primary", "to": "private-result"}
READ_SYNTHETIC = (("body", "payload"), ("calendar", "resource"), ("to", "destination"))
LIST_SEPARATOR = "; "
SUITES = ("workspace", "banking", "slack", "travel")
# The official AgentDojo v1.2.2 functions of each suite (pinned against the
# installed package by a test). A deployment serves exactly one suite, so the
# owner's task context never lists another suite's tools.
SUITE_TOOLS = {
    "workspace": frozenset((
        "add_calendar_event_participants", "append_to_file", "cancel_calendar_event", "create_calendar_event",
        "create_file", "delete_email", "delete_file", "get_current_day", "get_day_calendar_events",
        "get_draft_emails", "get_file_by_id", "get_received_emails", "get_sent_emails", "get_unread_emails",
        "list_files", "reschedule_calendar_event", "search_calendar_events", "search_contacts_by_email",
        "search_contacts_by_name", "search_emails", "search_files", "search_files_by_filename", "send_email",
        "share_file")),
    "banking": frozenset((
        "get_balance", "get_iban", "get_most_recent_transactions", "get_scheduled_transactions",
        "get_user_info", "read_file", "schedule_transaction", "send_money", "update_password",
        "update_scheduled_transaction", "update_user_info")),
    "slack": frozenset((
        "add_user_to_channel", "get_channels", "get_users_in_channel", "get_webpage", "invite_user_to_slack",
        "post_webpage", "read_channel_messages", "read_inbox", "remove_user_from_slack",
        "send_channel_message", "send_direct_message")),
    "travel": frozenset((
        "cancel_calendar_event", "check_restaurant_opening_hours", "create_calendar_event",
        "get_all_car_rental_companies_in_city", "get_all_hotels_in_city", "get_all_restaurants_in_city",
        "get_car_fuel_options", "get_car_price_per_day", "get_car_rental_address", "get_car_types_available",
        "get_contact_information_for_restaurants", "get_cuisine_type_for_restaurants",
        "get_day_calendar_events", "get_dietary_restrictions_for_all_restaurants", "get_flight_information",
        "get_hotels_address", "get_hotels_prices", "get_price_for_restaurants",
        "get_rating_reviews_for_car_rental", "get_rating_reviews_for_hotels",
        "get_rating_reviews_for_restaurants", "get_restaurants_address", "get_user_information",
        "reserve_car_rental", "reserve_hotel", "reserve_restaurant", "search_calendar_events", "send_email")),
}

# kind -> (official argument may be omitted when the text is empty)
KINDS = {"text": False, "opt_text": True, "null_text": False, "list": False, "opt_list": True, "number": False,
         "opt_number": True, "integer": False, "opt_integer": True, "boolean": False,
         "opt_boolean": True, "permission": False, "attachments": True}


def _read(operation, upstream, *params):
    """A read tool: synthetic body/calendar/to plus parameter fields."""
    fields = [(n, r, None, "fixed") for n, r in READ_SYNTHETIC]
    fields += [(name, "parameter", name, kind) for name, kind in params]
    return dict(operation=operation, upstream=upstream, effect="read", fields=tuple(fields))


def _write(operation, upstream, effect, *fields):
    """A write tool: (adapter name, role, upstream name or None, kind). Missing
    resource/destination/payload roles are filled with the fixed synthetic
    fields; an upstream argument named like a synthetic field is renamed."""
    fields = list(fields)
    for name, role in READ_SYNTHETIC:
        if not any(f[1] == role for f in fields):
            if any(f[0] == name for f in fields):
                raise ValueError("synthetic_field_collision")
            fields.append((name, role, None, "fixed"))
    return dict(operation=operation, upstream=upstream, effect=effect, fields=tuple(fields))


P = "parameter"
CATALOG = (
    # --- the original workspace catalog, unchanged ---
    _read("dojo.calendar.search", "search_calendar_events", ("date", "text"), ("query", "text")),
    _read("dojo.calendar.day", "get_day_calendar_events", ("day", "text")),
    _read("dojo.email.search", "search_emails", ("query", "text")),
    _read("dojo.email.unread", "get_unread_emails"),
    _read("dojo.file.list", "list_files"),
    _read("dojo.file.search_name", "search_files_by_filename", ("filename", "text")),
    _read("dojo.file.search", "search_files", ("query", "text")),
    _write("dojo.file.append", "append_to_file", "update",
           ("content", P, "content", "text"), ("file_id", "resource", "file_id", "text")),
    # --- workspace reads ---
    _read("dojo.calendar.search_any", "search_calendar_events", ("query", "text")),
    _read("dojo.calendar.today", "get_current_day"),
    _read("dojo.email.search_sender", "search_emails", ("query", "text"), ("sender", "text")),
    _read("dojo.email.sent", "get_sent_emails"),
    _read("dojo.email.received", "get_received_emails"),
    _read("dojo.email.drafts", "get_draft_emails"),
    _read("dojo.contacts.search_name", "search_contacts_by_name", ("query", "text")),
    _read("dojo.contacts.search_email", "search_contacts_by_email", ("query", "text")),
    _read("dojo.file.get", "get_file_by_id", ("file_id", "text")),
    # --- workspace writes (calendar and email also serve travel) ---
    _write("dojo.email.send", "send_email", "send",
           ("recipients", "destination", "recipients", "list"), ("subject", P, "subject", "text"),
           ("text", P, "body", "text"), ("cc", P, "cc", "opt_list"), ("bcc", P, "bcc", "opt_list"),
           ("attachments", P, "attachments", "attachments")),
    _write("dojo.email.delete", "delete_email", "delete", ("email_id", "resource", "email_id", "text")),
    _write("dojo.calendar.create", "create_calendar_event", "create",
           ("title", P, "title", "text"), ("start_time", P, "start_time", "text"),
           ("end_time", P, "end_time", "text"), ("description", P, "description", "text"),
           ("participants", "destination", "participants", "opt_list"),
           ("location", P, "location", "opt_text")),
    _write("dojo.calendar.cancel", "cancel_calendar_event", "delete",
           ("event_id", "resource", "event_id", "text")),
    _write("dojo.calendar.reschedule", "reschedule_calendar_event", "update",
           ("event_id", "resource", "event_id", "text"), ("new_start_time", P, "new_start_time", "text"),
           ("new_end_time", P, "new_end_time", "opt_text")),
    _write("dojo.calendar.add_participants", "add_calendar_event_participants", "update",
           ("event_id", "resource", "event_id", "text"),
           ("participants", "destination", "participants", "list")),
    _write("dojo.file.create", "create_file", "create",
           ("filename", "resource", "filename", "text"), ("content", P, "content", "text")),
    _write("dojo.file.delete", "delete_file", "delete", ("file_id", "resource", "file_id", "text")),
    _write("dojo.file.share", "share_file", "send",
           ("file_id", "resource", "file_id", "text"), ("email", "destination", "email", "text"),
           ("permission", P, "permission", "permission")),
    # --- banking ---
    _read("dojo.bank.iban", "get_iban"),
    _read("dojo.bank.balance", "get_balance"),
    _read("dojo.bank.recent", "get_most_recent_transactions", ("n", "opt_integer")),
    _read("dojo.bank.scheduled", "get_scheduled_transactions"),
    _read("dojo.bank.read_file", "read_file", ("file_path", "text")),
    _read("dojo.bank.user_info", "get_user_info"),
    _write("dojo.bank.send_money", "send_money", "send",
           ("recipient", "destination", "recipient", "text"), ("amount", P, "amount", "number"),
           ("subject", P, "subject", "text"), ("date", P, "date", "text")),
    _write("dojo.bank.schedule", "schedule_transaction", "create",
           ("recipient", "destination", "recipient", "text"), ("amount", P, "amount", "number"),
           ("subject", P, "subject", "text"), ("date", P, "date", "text"),
           ("recurring", P, "recurring", "boolean")),
    _write("dojo.bank.update_scheduled", "update_scheduled_transaction", "update",
           ("id", "resource", "id", "integer"), ("recipient", "destination", "recipient", "opt_text"),
           ("amount", P, "amount", "opt_number"), ("subject", P, "subject", "opt_text"),
           ("date", P, "date", "opt_text"), ("recurring", P, "recurring", "opt_boolean")),
    _write("dojo.bank.update_password", "update_password", "update", ("password", P, "password", "text")),
    _write("dojo.bank.update_user", "update_user_info", "update",
           ("first_name", P, "first_name", "opt_text"), ("last_name", P, "last_name", "opt_text"),
           ("street", P, "street", "opt_text"), ("city", P, "city", "opt_text")),
    # --- slack ---
    _read("dojo.slack.channels", "get_channels"),
    _read("dojo.slack.read_channel", "read_channel_messages", ("channel", "text")),
    _read("dojo.slack.read_inbox", "read_inbox", ("user", "text")),
    _read("dojo.slack.channel_users", "get_users_in_channel", ("channel", "text")),
    _read("dojo.web.get", "get_webpage", ("url", "text")),
    _write("dojo.slack.add_user", "add_user_to_channel", "update",
           ("channel", "resource", "channel", "text"), ("user", "destination", "user", "text")),
    _write("dojo.slack.send_dm", "send_direct_message", "send",
           ("recipient", "destination", "recipient", "text"), ("text", P, "body", "text")),
    _write("dojo.slack.send_channel", "send_channel_message", "send",
           ("channel", "destination", "channel", "text"), ("text", P, "body", "text")),
    _write("dojo.slack.invite", "invite_user_to_slack", "send",
           ("user", "resource", "user", "text"), ("user_email", "destination", "user_email", "text")),
    _write("dojo.slack.remove", "remove_user_from_slack", "delete", ("user", "resource", "user", "text")),
    _write("dojo.web.post", "post_webpage", "send",
           ("url", "destination", "url", "text"), ("content", P, "content", "text")),
    # --- travel ---
    _read("dojo.travel.user_info", "get_user_information"),
    _read("dojo.travel.hotels", "get_all_hotels_in_city", ("city", "text")),
    _read("dojo.travel.hotel_prices", "get_hotels_prices", ("hotel_names", "list")),
    _read("dojo.travel.hotel_reviews", "get_rating_reviews_for_hotels", ("hotel_names", "list")),
    _read("dojo.travel.hotel_address", "get_hotels_address", ("hotel_name", "text")),
    _read("dojo.travel.restaurants", "get_all_restaurants_in_city", ("city", "text")),
    _read("dojo.travel.restaurant_cuisine", "get_cuisine_type_for_restaurants", ("restaurant_names", "list")),
    _read("dojo.travel.restaurant_address", "get_restaurants_address", ("restaurant_names", "list")),
    _read("dojo.travel.restaurant_reviews", "get_rating_reviews_for_restaurants", ("restaurant_names", "list")),
    _read("dojo.travel.restaurant_dietary", "get_dietary_restrictions_for_all_restaurants",
          ("restaurant_names", "list")),
    _read("dojo.travel.restaurant_contact", "get_contact_information_for_restaurants",
          ("restaurant_names", "list")),
    _read("dojo.travel.restaurant_prices", "get_price_for_restaurants", ("restaurant_names", "list")),
    _read("dojo.travel.restaurant_hours", "check_restaurant_opening_hours", ("restaurant_names", "list")),
    _read("dojo.travel.car_companies", "get_all_car_rental_companies_in_city", ("city", "text")),
    _read("dojo.travel.car_types", "get_car_types_available", ("company_name", "list")),
    _read("dojo.travel.car_reviews", "get_rating_reviews_for_car_rental", ("company_name", "list")),
    _read("dojo.travel.car_fuel", "get_car_fuel_options", ("company_name", "list")),
    _read("dojo.travel.car_address", "get_car_rental_address", ("company_name", "list")),
    _read("dojo.travel.car_prices", "get_car_price_per_day", ("company_name", "list")),
    _read("dojo.travel.flights", "get_flight_information", ("departure_city", "text"), ("arrival_city", "text")),
    _write("dojo.travel.reserve_hotel", "reserve_hotel", "create",
           ("hotel", "resource", "hotel", "text"), ("start_day", P, "start_day", "text"),
           ("end_day", P, "end_day", "text")),
    _write("dojo.travel.reserve_car", "reserve_car_rental", "create",
           ("company", "resource", "company", "text"), ("start_time", P, "start_time", "text"),
           ("end_time", P, "end_time", "null_text")),
    _write("dojo.travel.reserve_restaurant", "reserve_restaurant", "create",
           ("restaurant", "resource", "restaurant", "text"), ("start_time", P, "start_time", "text")),
)

_NUMBER = re.compile(r"(0|[1-9][0-9]{0,11})(\.[0-9]{1,6})?\Z")
_INTEGER = re.compile(r"(0|[1-9][0-9]{0,11})\Z")


def entry(operation):
    for tool in CATALOG:
        if tool["operation"] == operation:
            return tool
    raise ValueError("unreviewed_tool")


def decode_argument(kind, text):
    """The official argument for one kernel-pinned text, or OMIT. Total and
    deterministic: any text it does not accept is refused, never guessed."""
    if type(text) is not str or kind not in KINDS:
        raise ValueError("adapter_argument")
    if text == "" and KINDS[kind]:
        return OMIT
    if kind == "null_text":
        return text or None
    if kind in ("text", "opt_text"):
        return text
    if kind in ("list", "opt_list", "attachments"):
        items = text.split(LIST_SEPARATOR)
        if any(not item or item != item.strip() for item in items):
            raise ValueError("adapter_list")
        if kind == "attachments":
            return [{"type": "file", "file_id": item} for item in items]
        return items
    if kind in ("number", "opt_number"):
        if not _NUMBER.match(text):
            raise ValueError("adapter_number")
        return float(text)
    if kind in ("integer", "opt_integer"):
        if not _INTEGER.match(text):
            raise ValueError("adapter_integer")
        return int(text)
    if kind in ("boolean", "opt_boolean"):
        if text not in ("true", "false"):
            raise ValueError("adapter_boolean")
        return text == "true"
    if kind == "permission":
        if text not in ("r", "rw"):
            raise ValueError("adapter_permission")
        return text
    raise ValueError("adapter_argument")


class _Omit:
    __slots__ = ()

    def __repr__(self):
        return "OMIT"


OMIT = _Omit()


def official_call(operation, arguments):
    """(upstream function, official arguments) for one adapter call, or a
    ValueError. Fixed synthetic fields must equal their sentinels and are
    dropped; every other field must be present and decodes by its rule."""
    tool = entry(operation)
    names = {f[0] for f in tool["fields"]}
    if type(arguments) is not dict or set(arguments) != names:
        raise ValueError("adapter_fields")
    official = {}
    for name, _role, upstream, kind in tool["fields"]:
        value = arguments[name]
        if kind == "fixed":
            if value != SENTINELS[name]:
                raise ValueError("adapter_control_mismatch")
            continue
        decoded = decode_argument(kind, value)
        if decoded is not OMIT:
            official[upstream] = decoded
    return tool["upstream"], official


def suite_operations(suite_tools):
    """The reviewed operations an environment can serve: those whose official
    function is one of this suite's tools."""
    names = set(suite_tools)
    return tuple(t["operation"] for t in CATALOG if t["upstream"] in names)


def catalog_document(suite, extra_write_tools=()):
    """Schema-2 catalog of one suite for the deployment generator: every field
    is text with an explicit role; authorizing tools carry intent-flow
    confinement. Catalog order is kept, so the original workspace tools lead."""
    served = set(suite_operations(SUITE_TOOLS[suite]))
    reads, writes = [], []
    for tool in CATALOG:
        if tool["operation"] not in served:
            continue
        fields = sorted(({"name": n, "role": r, "type": "text"} for n, r, _u, _k in tool["fields"]),
                        key=lambda f: f["name"])
        item = {"operation": tool["operation"], "effect": tool["effect"], "fixed_magnitude": 1,
                "fields": fields}
        if tool["effect"] == "read":
            reads.append(item)
        else:
            writes.append(dict(item, validators=["intent_flow_confinement"]))
    return {"schema": 2, "read_tools": reads, "write_tools": writes + list(extra_write_tools)}
