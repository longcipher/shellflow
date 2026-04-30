# src/config.py
import re

def parse_server_config(script):
    servers = {}
    lines = script.split('\n')
    current_server = None
    for line in lines:
        if line.startswith('# @SERVER '):
            current_server = line.split('# @SERVER ')[1].strip()
            servers[current_server] = {}
        elif current_server and line.strip().startswith('#   '):
            key, value = line.strip()[4:].split(': ', 1)
            servers[current_server][key.strip()] = value.strip()
    return servers