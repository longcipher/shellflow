# src/config.py

def parse_server_config(script):
    """
    Parse server configurations from shellflow script comments.

    Expected format:
    # @SERVER server-name
    #   host: example.com
    #   user: deploy
    #   port: 22
    #   key: ~/.ssh/id_rsa

    Args:
        script: The shellflow script content as a string

    Returns:
        dict: Dictionary mapping server names to their configuration dicts

    Raises:
        ValueError: If required fields are missing or malformed configuration is found
    """
    servers = {}
    lines = script.split('\n')
    current_server = None

    for line_num, line in enumerate(lines, 1):
        line = line.strip()

        # Skip empty lines and pure comments (not server definitions or config lines)
        if not line or (line.startswith('#') and not line.startswith('# @SERVER') and not (current_server and line.startswith('#   '))):
            continue

        if line.startswith('# @SERVER'):
            parts = line.split('# @SERVER', 1)
            if len(parts) < 2 or not parts[1].strip():
                raise ValueError(f"Line {line_num}: Server name cannot be empty")
            current_server = parts[1].strip()
            servers[current_server] = {}
        elif current_server and line.startswith('#   '):
            config_line = line[4:]  # Remove '#   ' prefix

            # Handle malformed config lines gracefully
            if ': ' not in config_line:
                raise ValueError(f"Line {line_num}: Malformed config line '{config_line}'. Expected format: 'key: value'")

            try:
                key, value = config_line.split(': ', 1)
                servers[current_server][key.strip()] = value.strip()
            except ValueError as e:
                raise ValueError(f"Line {line_num}: Failed to parse config line '{config_line}': {e}")

    # Validate required fields for each server
    for server_name, config in servers.items():
        if 'host' not in config:
            raise ValueError(f"Server '{server_name}': Missing required field 'host'")

    return servers