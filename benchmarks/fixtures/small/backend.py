import subprocess

def run_user_command(value):
    subprocess.run(value, shell=True)
