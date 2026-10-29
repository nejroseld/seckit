import subprocess
import requests

def run_command(value):
    subprocess.run(value, shell=True)

def lookup(cursor, request):
    # Tainted query value should be reported; fixture is inert and never executed.
    cursor.execute("SELECT * FROM users WHERE name = '" + request.args.get("name") + "'")

def proxy(request):
    return requests.get(request.args.get("url"))
