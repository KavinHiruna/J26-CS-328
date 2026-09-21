import re
import urllib.parse
import pandas as pd


SQL_KEYWORDS = [
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "from",
    "where",
    "having",
    "group by",
    "order by",
    "sleep",
    "benchmark",
    "pg_sleep",
    "extractvalue",
    "updatexml",
    "cast",
    "convert",
    "concat",
    "substring",
    "database",
    "schema",
    "information_schema"
]


def safe_text(value):
    if pd.isna(value):
        return ""
    
    value = str(value)

    if value in ["0", "0.0", "nan", "None"]:
        return ""

    return value


def extract_sql_features(row):

    query = safe_text(row.get("http.request.uri.query"))
    full_uri = safe_text(row.get("http.request.full_uri"))
    payload = safe_text(row.get("tcp.payload"))

    # URL decode
    decoded_query = urllib.parse.unquote_plus(query).lower()

    features = {}

    # -------------------------
    # HTTP features
    # -------------------------

    features["query_length"] = len(query)

    features["query_parameter_count"] = (
        query.count("&") + 1 if query else 0
    )

    features["uri_length"] = len(full_uri)

    features["http_get"] = (
        1 if safe_text(row.get("http.request.method")).upper() == "GET"
        else 0
    )

    # -------------------------
    # SQL syntax features
    # -------------------------

    features["single_quote_count"] = decoded_query.count("'")

    features["double_quote_count"] = decoded_query.count('"')

    features["semicolon_count"] = decoded_query.count(";")

    features["comment_count"] = (
        decoded_query.count("--") +
        decoded_query.count("/*") +
        decoded_query.count("#")
    )

    features["parenthesis_count"] = (
        decoded_query.count("(") +
        decoded_query.count(")")
    )

    features["equals_count"] = decoded_query.count("=")

    # -------------------------
    # SQL keyword features
    # -------------------------

    for keyword in SQL_KEYWORDS:

        feature_name = (
            "sql_" +
            keyword.replace(" ", "_")
            .replace("-", "_")
        )

        features[feature_name] = decoded_query.count(keyword)

    # -------------------------
    # SQL operator patterns
    # -------------------------

    features["or_condition"] = len(
        re.findall(r"\bor\b", decoded_query)
    )

    features["and_condition"] = len(
        re.findall(r"\band\b", decoded_query)
    )

    features["union_select"] = len(
        re.findall(r"\bunion\s+select\b", decoded_query)
    )

    # -------------------------
    # Encoding characteristics
    # -------------------------

    features["percent_encoded_count"] = len(
        re.findall(r"%[0-9a-fA-F]{2}", query)
    )

    features["hex_pattern_count"] = len(
        re.findall(r"0x[0-9a-f]+", decoded_query)
    )

    # -------------------------
    # Suspicious functions
    # -------------------------

    features["sleep_function"] = int(
        "sleep(" in decoded_query or
        "pg_sleep(" in decoded_query
    )

    features["database_function"] = int(
        "database(" in decoded_query or
        "information_schema" in decoded_query
    )

    features["extractvalue_function"] = int(
        "extractvalue" in decoded_query
    )

    features["xml_function"] = int(
        "updatexml" in decoded_query or
        "xmltype" in decoded_query
    )

    # -------------------------
    # Network features
    # -------------------------

    numeric_features = [
        "tcp.len",
        "tcp.dstport",
        "tcp.srcport",
        "tcp.flags.ack",
        "tcp.connection.syn",
        "tcp.connection.synack",
        "tcp.connection.fin",
        "tcp.connection.rst",
        "http.content_length"
    ]

    for feature in numeric_features:

        value = row.get(feature, 0)

        try:
            features[feature] = float(value)
        except:
            features[feature] = 0.0

    # TCP payload size
    features["tcp_payload_length"] = len(payload)

    return features