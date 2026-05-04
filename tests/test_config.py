# tests/test_config.py
import pytest

from shellflow import ParseError
from shellflow.config import parse_server_config


def test_parse_server_definition():
    script = """
# @SERVER web-server
#   host: example.com
#   user: deploy
#   port: 22
#   key: ~/.ssh/id_rsa
"""
    config = parse_server_config(script)
    assert config["web-server"]["host"] == "example.com"
    assert config["web-server"]["user"] == "deploy"
    assert config["web-server"]["port"] == "22"
    assert config["web-server"]["key"] == "~/.ssh/id_rsa"


def test_parse_multiple_servers():
    script = """
# @SERVER web-server
#   host: example.com
#   user: deploy

# @SERVER db-server
#   host: db.example.com
#   user: admin
#   port: 2222
"""
    config = parse_server_config(script)
    assert config["web-server"]["host"] == "example.com"
    assert config["web-server"]["user"] == "deploy"
    assert config["db-server"]["host"] == "db.example.com"
    assert config["db-server"]["user"] == "admin"
    assert config["db-server"]["port"] == "2222"


def test_parse_with_comments_and_empty_lines():
    script = """
# This is a comment
# @SERVER web-server
#   host: example.com

# Another comment
#   user: deploy

# @SERVER db-server
#   host: db.example.com
"""
    config = parse_server_config(script)
    assert len(config) == 2
    assert config["web-server"]["host"] == "example.com"
    assert config["web-server"]["user"] == "deploy"
    assert config["db-server"]["host"] == "db.example.com"


def test_missing_required_host_field():
    script = """
# @SERVER web-server
#   user: deploy
#   port: 22
"""
    with pytest.raises(ParseError, match="Missing required field 'host'"):
        parse_server_config(script)


def test_malformed_config_line():
    script = """
# @SERVER web-server
#   host: example.com
#   invalid line without colon
"""
    with pytest.raises(ParseError, match="Malformed config line"):
        parse_server_config(script)


def test_empty_server_name():
    script = """
# @SERVER
#   host: example.com
"""
    with pytest.raises(ParseError, match="Server name cannot be empty"):
        parse_server_config(script)


def test_empty_config():
    script = ""
    config = parse_server_config(script)
    assert config == {}


def test_config_with_only_comments():
    script = """
# This is just a comment
# Another comment
"""
    config = parse_server_config(script)
    assert config == {}


def test_config_line_with_multiple_colons():
    script = """
# @SERVER web-server
#   host: example.com:8080
#   user: deploy
"""
    config = parse_server_config(script)
    assert config["web-server"]["host"] == "example.com:8080"
    assert config["web-server"]["user"] == "deploy"
