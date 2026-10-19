"""Tests for docsgpt/agents/tools/postgres.py"""

import ipaddress
from unittest.mock import MagicMock, patch

import pytest

from docsgpt.agents.tools.postgres import (
    PostgresTool,
    validate_and_pin_postgres_conninfo,
)
from docsgpt.security.safe_url import UnsafeUserUrlError


@pytest.fixture
def tool():
    return PostgresTool(
        config={"token": "postgresql://user:pass@93.184.216.34/testdb"}
    )


@pytest.mark.unit
class TestPostgresExecuteAction:
    def test_unknown_action_raises(self, tool):
        with pytest.raises(ValueError, match="Unknown action"):
            tool.execute_action("invalid")

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_select_query(self, mock_connect, tool):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.description = [("id",), ("name",)]
        mock_cur.fetchall.return_value = [(1, "Alice"), (2, "Bob")]
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        result = tool.execute_action(
            "postgres_execute_sql", sql_query="SELECT id, name FROM users"
        )

        assert result["status_code"] == 200
        assert result["response_data"]["column_names"] == ["id", "name"]
        assert len(result["response_data"]["data"]) == 2
        assert result["response_data"]["data"][0] == {"id": 1, "name": "Alice"}
        mock_conn.close.assert_called_once()

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_insert_query(self, mock_connect, tool):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.rowcount = 1
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        result = tool.execute_action(
            "postgres_execute_sql",
            sql_query="INSERT INTO users (name) VALUES ('Alice')",
        )

        assert result["status_code"] == 200
        assert "1 rows affected" in result["response_data"]["message"]
        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_db_error(self, mock_connect, tool):
        import psycopg

        mock_connect.side_effect = psycopg.Error("connection refused")

        result = tool.execute_action(
            "postgres_execute_sql", sql_query="SELECT 1"
        )

        assert result["status_code"] == 500
        assert "Database error" in result["error"]

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_get_schema(self, mock_connect, tool):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchall.return_value = [
            ("users", "id", "integer", "nextval(...)", "NO"),
            ("users", "name", "varchar", None, "YES"),
            ("posts", "id", "integer", "nextval(...)", "NO"),
        ]
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        result = tool.execute_action("postgres_get_schema", db_name="testdb")

        assert result["status_code"] == 200
        assert "users" in result["schema"]
        assert "posts" in result["schema"]
        assert len(result["schema"]["users"]) == 2
        assert result["schema"]["users"][0]["column_name"] == "id"
        mock_conn.close.assert_called_once()

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_get_schema_without_db_name(self, mock_connect, tool):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchall.return_value = [("users", "id", "integer", None, "NO")]
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        result = tool.execute_action("postgres_get_schema")

        assert result["status_code"] == 200
        assert "users" in result["schema"]

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_get_schema_db_error(self, mock_connect, tool):
        import psycopg

        mock_connect.side_effect = psycopg.Error("auth failed")

        result = tool.execute_action("postgres_get_schema", db_name="testdb")

        assert result["status_code"] == 500
        assert "Database error" in result["error"]

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_connection_closed_on_error(self, mock_connect, tool):
        import psycopg

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.execute.side_effect = psycopg.Error("syntax error")
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        tool.execute_action("postgres_execute_sql", sql_query="BAD SQL")

        mock_conn.close.assert_called_once()

    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_select_with_no_description(self, mock_connect, tool):
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.description = None
        mock_cur.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn

        result = tool.execute_action(
            "postgres_execute_sql", sql_query="SELECT 1 WHERE false"
        )

        assert result["status_code"] == 200
        assert result["response_data"]["column_names"] == []


@pytest.mark.unit
class TestPostgresMetadata:
    def test_actions_metadata(self, tool):
        meta = tool.get_actions_metadata()
        assert len(meta) == 2
        names = {a["name"] for a in meta}
        assert "postgres_execute_sql" in names
        assert "postgres_get_schema" in names

    def test_get_schema_takes_no_required_arguments(self, tool):
        action = next(a for a in tool.get_actions_metadata() if a["name"] == "postgres_get_schema")
        assert action["parameters"].get("required", []) == []

    def test_config_requirements(self, tool):
        reqs = tool.get_config_requirements()
        assert "token" in reqs
        assert reqs["token"]["secret"] is True


@pytest.mark.unit
class TestPostgresSSRFProtection:
    @pytest.mark.parametrize(
        "unsafe_conn_str",
        [
            "postgresql://user:pass@localhost:5432/db",
            "postgresql://user:pass@127.0.0.1:5432/db",
            "postgresql://user:pass@10.0.0.5:5432/db",
            "postgresql://user:pass@169.254.169.254:5432/db",
            "postgresql://user:pass@[::1]:5432/db",
            "postgresql://user:pass@metadata.google.internal:5432/db",
            "postgresql:///db",
            "host=/var/run/postgresql dbname=db",
            "host=93.184.216.34 dbname=db passfile=/etc/passwd",
            "host=93.184.216.34 dbname=db sslrootcert=/etc/shadow",
            "host=93.184.216.34,127.0.0.1 dbname=db",
        ],
    )
    @patch("docsgpt.agents.tools.postgres.psycopg.connect")
    def test_rejects_unsafe_connection_strings(
        self, mock_connect, unsafe_conn_str
    ):
        with pytest.raises(UnsafeUserUrlError):
            validate_and_pin_postgres_conninfo(unsafe_conn_str)

        bad_tool = PostgresTool(config={"token": unsafe_conn_str})
        sql_res = bad_tool.execute_action(
            "postgres_execute_sql", sql_query="SELECT 1"
        )
        assert sql_res["status_code"] == 400
        assert "Invalid connection string" in sql_res["error"]

        schema_res = bad_tool.execute_action("postgres_get_schema")
        assert schema_res["status_code"] == 400
        assert "Invalid connection string" in schema_res["error"]
        mock_connect.assert_not_called()

    @patch("docsgpt.agents.tools.postgres._resolve")
    def test_rejects_dns_resolving_to_private_ip(self, mock_resolve):
        mock_resolve.return_value = [
            ipaddress.ip_address("93.184.216.34"),
            ipaddress.ip_address("10.0.0.1"),
        ]
        with pytest.raises(UnsafeUserUrlError, match="blocked address"):
            validate_and_pin_postgres_conninfo(
                "postgresql://user:pass@db.example.com:5432/prod"
            )

    @patch("docsgpt.agents.tools.postgres._resolve")
    def test_pins_resolved_public_ip_into_hostaddr(self, mock_resolve):
        mock_resolve.return_value = [ipaddress.ip_address("93.184.216.34")]
        pinned = validate_and_pin_postgres_conninfo(
            "postgresql://user:pass@db.example.com:5432/prod"
        )
        assert "hostaddr=93.184.216.34" in pinned

    def test_rejects_application_postgres_uri(self, monkeypatch):
        from docsgpt.core.settings import settings

        monkeypatch.setattr(
            settings,
            "POSTGRES_URI",
            "postgresql://app:secret@93.184.216.34:5432/docsgpt",
        )
        with pytest.raises(
            UnsafeUserUrlError, match="cannot target the application database"
        ):
            validate_and_pin_postgres_conninfo(
                "postgresql://app:secret@93.184.216.34:5432/docsgpt"
            )
