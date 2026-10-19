import ipaddress
import logging
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from docsgpt.agents.tools.base import Tool
from docsgpt.core.settings import settings
from docsgpt.security.safe_url import UnsafeUserUrlError, _is_blocked_ip, _resolve

logger = logging.getLogger(__name__)


def _reject_unsafe_host(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve a PostgreSQL host and return a validated address to pin."""
    if not host:
        raise UnsafeUserUrlError("connection string has no hostname")

    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None

    if literal is not None:
        if _is_blocked_ip(literal):
            raise UnsafeUserUrlError(f"hostname {host!r} resolves to blocked address {literal}")
        return literal

    addresses = list(_resolve(host))
    if not addresses:
        raise UnsafeUserUrlError(f"hostname {host!r} returned no addresses")
    for address in addresses:
        if _is_blocked_ip(address):
            raise UnsafeUserUrlError(
                f"hostname {host!r} resolves to blocked address {address}"
            )
    return addresses[0]


def validate_and_pin_postgres_conninfo(conninfo: str) -> str:
    """Validate a user PostgreSQL connection string and pin its host address.

    User-controlled PostgreSQL connection strings must never be allowed to
    reach local/private networks, Unix sockets, or filesystem-backed client
    configuration. DNS is resolved once and the resulting public IP is
    supplied as ``hostaddr`` so the eventual connection cannot silently
    resolve the hostname again to a different address.
    """
    if not isinstance(conninfo, str) or not conninfo.strip():
        raise UnsafeUserUrlError("connection string must be a non-empty string")

    candidate = conninfo.strip()
    configured_app_uri = str(getattr(settings, "POSTGRES_URI", "") or "").strip()
    if configured_app_uri and candidate == configured_app_uri:
        raise UnsafeUserUrlError("connection string cannot target the application database")

    # PostgreSQL URI form.
    if candidate.lower().startswith(("postgresql://", "postgres://")):
        try:
            parts = urlsplit(candidate)
        except ValueError as exc:
            raise UnsafeUserUrlError(f"invalid connection string: {exc}") from exc

        host = parts.hostname
        if not host:
            raise UnsafeUserUrlError("connection string has no hostname")

        if "," in host:
            raise UnsafeUserUrlError("multiple PostgreSQL hosts are not allowed")

        pinned_ip = _reject_unsafe_host(host)
        if "@" not in parts.netloc:
            raise UnsafeUserUrlError("connection string has no userinfo")

        query = parse_qsl(parts.query, keep_blank_values=True)
        query = [(key, value) for key, value in query if key.lower() != "hostaddr"]
        query.append(("hostaddr", str(pinned_ip)))
        pinned_query = urlencode(query)
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, pinned_query, parts.fragment)
        )

    # Keyword/value PostgreSQL conninfo form.
    try:
        values = conninfo_to_dict(candidate)
    except Exception as exc:
        raise UnsafeUserUrlError(f"invalid connection string: {exc}") from exc

    host = values.get("host")
    if not host:
        raise UnsafeUserUrlError("connection string must specify a TCP host")
    if "," in host:
        raise UnsafeUserUrlError("multiple PostgreSQL hosts are not allowed")
    if host.startswith("/"):
        raise UnsafeUserUrlError("Unix socket hosts are not allowed")

    forbidden_path_options = ("passfile", "sslcert", "sslkey", "sslrootcert", "sslcrl")
    for option in forbidden_path_options:
        value = values.get(option)
        if value and value.startswith(("/", "~", "\\")):
            raise UnsafeUserUrlError(f"filesystem option {option} is not allowed")

    pinned_ip = _reject_unsafe_host(host)
    values["hostaddr"] = str(pinned_ip)
    return make_conninfo(**values)


class PostgresTool(Tool):
    """
    PostgreSQL Database Tool
    A tool for connecting to a PostgreSQL database using a connection string,
    executing SQL queries, and retrieving schema information.
    """

    def __init__(self, config):
        self.config = config
        self.connection_string = config.get("token", "")

    def execute_action(self, action_name, **kwargs):
        actions = {
            "postgres_execute_sql": self._execute_sql,
            "postgres_get_schema": self._get_schema,
        }
        if action_name not in actions:
            raise ValueError(f"Unknown action: {action_name}")
        return actions[action_name](**kwargs)

    def _safe_connection_string(self):
        return validate_and_pin_postgres_conninfo(self.connection_string)

    def _execute_sql(self, sql_query):
        """Execute an SQL query against the validated PostgreSQL database."""
        conn = None
        try:
            conn = psycopg.connect(self._safe_connection_string())
            cur = conn.cursor()
            cur.execute(sql_query)
            conn.commit()

            if sql_query.strip().lower().startswith("select"):
                column_names = (
                    [desc[0] for desc in cur.description] if cur.description else []
                )
                results = []
                rows = cur.fetchall()
                for row in rows:
                    results.append(dict(zip(column_names, row)))
                response_data = {"data": results, "column_names": column_names}
            else:
                row_count = cur.rowcount
                response_data = {
                    "message": f"Query executed successfully, {row_count} rows affected."
                }

            cur.close()
            return {
                "status_code": 200,
                "message": "SQL query executed successfully.",
                "response_data": response_data,
            }

        except UnsafeUserUrlError as e:
            logger.warning("Rejected unsafe PostgreSQL connection string: %s", e)
            return {
                "status_code": 400,
                "message": "Invalid connection string.",
                "error": f"Invalid connection string: {e}",
            }
        except psycopg.Error as e:
            error_message = f"Database error: {e}"
            logger.error("PostgreSQL execute_sql error: %s", e)
            return {
                "status_code": 500,
                "message": "Failed to execute SQL query.",
                "error": error_message,
            }
        finally:
            if conn:
                conn.close()

    def _get_schema(self, db_name=None):
        """Retrieve the schema of the validated PostgreSQL database."""
        conn = None
        try:
            conn = psycopg.connect(self._safe_connection_string())
            cur = conn.cursor()

            cur.execute(
                """
                SELECT
                    table_name,
                    column_name,
                    data_type,
                    column_default,
                    is_nullable
                FROM
                    information_schema.columns
                WHERE
                    table_schema = 'public'
                ORDER BY
                    table_name,
                    ordinal_position;
            """
            )

            schema_data = {}
            for row in cur.fetchall():
                table_name, column_name, data_type, column_default, is_nullable = row
                if table_name not in schema_data:
                    schema_data[table_name] = []
                schema_data[table_name].append(
                    {
                        "column_name": column_name,
                        "data_type": data_type,
                        "column_default": column_default,
                        "is_nullable": is_nullable,
                    }
                )

            cur.close()
            return {
                "status_code": 200,
                "message": "Database schema retrieved successfully.",
                "schema": schema_data,
            }

        except UnsafeUserUrlError as e:
            logger.warning("Rejected unsafe PostgreSQL connection string: %s", e)
            return {
                "status_code": 400,
                "message": "Invalid connection string.",
                "error": f"Invalid connection string: {e}",
            }
        except psycopg.Error as e:
            error_message = f"Database error: {e}"
            logger.error("PostgreSQL get_schema error: %s", e)
            return {
                "status_code": 500,
                "message": "Failed to retrieve database schema.",
                "error": error_message,
            }
        finally:
            if conn:
                conn.close()

    def get_actions_metadata(self):
        return [
            {
                "name": "postgres_execute_sql",
                "access": "write",
                "description": (
                    "Execute an SQL query against the PostgreSQL database and return the results. "
                    "Use this tool to interact with the database, e.g., retrieve specific data or perform updates. "
                    "Only SELECT queries will return data, other queries will return execution status."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql_query": {
                            "type": "string",
                            "description": "The SQL query to execute.",
                        },
                    },
                    "required": ["sql_query"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "postgres_get_schema",
                "access": "read",
                "description": (
                    "Retrieve the schema of the PostgreSQL database, including tables and their columns. "
                    "Use this to understand the database structure before executing queries."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
            },
        ]

    def get_config_requirements(self):
        return {
            "token": {
                "type": "string",
                "label": "Connection String",
                "description": "PostgreSQL database connection string",
                "required": True,
                "secret": True,
                "order": 1,
            },
        }
