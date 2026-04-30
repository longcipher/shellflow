# tests/test_config.py
from src.config import parse_server_config

def test_parse_server_definition():
    script = """
# @SERVER web-server
#   host: example.com
#   user: deploy
#   port: 22
#   key: ~/.ssh/id_rsa
"""
    config = parse_server_config(script)
    assert config['web-server']['host'] == 'example.com'
    assert config['web-server']['user'] == 'deploy'