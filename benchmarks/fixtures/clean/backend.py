import subprocess
import requests
from urllib.parse import urlparse

def run_command(value):
    subprocess.run(["/usr/bin/example-tool", value], check=True)

def lookup(cursor, request):
    cursor.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),))

def proxy(url, allowed_hosts):
    if urlparse(url).hostname not in allowed_hosts:
        raise ValueError("untrusted host")
    return requests.get(url)
