"""
Run a command in a tmux session and send input via tmux send-keys / paste-buffer.
"""
import os
import subprocess
import time


def _check_tmux():
    if subprocess.run(["which", "tmux"], capture_output=True).returncode != 0:
        raise RuntimeError("tmux is not installed. Please install tmux to use TmuxProcess.")


def _find_terminal():
    for name in ["xterm", "gnome-terminal", "konsole", "alacritty", "terminator", "xfce4-terminal"]:
        if subprocess.run(["which", name], capture_output=True).returncode == 0:
            return name
    return None


class TmuxProcess:
    """Process-like interface that runs a command in a tmux session and sends input via tmux."""

    def __init__(self, session_name):
        self.session_name = session_name

    def sendline(self, data):
        if isinstance(data, bytes):
            load_proc = subprocess.Popen(
                ["tmux", "load-buffer", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            load_proc.stdin.write(data)
            load_proc.stdin.close()
            load_proc.wait()

            subprocess.run(
                ["tmux", "paste-buffer", "-t", self.session_name, "-d"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["tmux", "send-keys", "-t", self.session_name, "Enter"],
                check=False,
            )
        else:
            data_str = str(data).replace("\n", "")
            subprocess.run(
                ["tmux", "send-keys", "-t", self.session_name, "-l", data_str, "Enter"],
                check=False,
            )
        time.sleep(0.1)

    def interactive(self):
        print(f"\nTmux session '{self.session_name}' is running in a separate terminal.")
        print("You can interact with it directly in that terminal.")
        print("Press Ctrl+C here to kill the session, or type 'quit' to exit.")
        try:
            while True:
                user_input = input()
                if user_input.lower() in ("quit", "exit", "q"):
                    break
                subprocess.run(
                    ["tmux", "send-keys", "-t", self.session_name, user_input, "Enter"],
                    check=False,
                )
        except KeyboardInterrupt:
            pass
        finally:
            subprocess.run(
                ["tmux", "kill-session", "-t", self.session_name],
                check=False,
            )


def spawn_in_tmux(command, cwd=None, attach_terminal=True):
    """
    Start a command in a new detached tmux session and return a TmuxProcess.

    command: list of args, e.g. ["python3", "game.py"]
    cwd: working directory (default: dir of script calling this)
    attach_terminal: if True, open a terminal window attached to the session
    """
    _check_tmux()

    session_name = f"game_{os.getpid()}"
    cwd = cwd or os.getcwd()

    cmd_str = " ".join(f"'{arg}'" if " " in str(arg) else str(arg) for arg in command)
    subprocess.run(
        [
            "tmux",
            "new-session",
            "-d",
            "-s",
            session_name,
            "bash",
            "-c",
            f"cd '{cwd}' && {cmd_str}; exec bash",
        ],
        check=True,
    )

    if attach_terminal:
        terminal_cmd = _find_terminal()
        if terminal_cmd:
            if terminal_cmd == "gnome-terminal":
                subprocess.Popen(
                    ["gnome-terminal", "--", "tmux", "attach", "-t", session_name],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    [terminal_cmd, "-e", "tmux", "attach", "-t", session_name],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            time.sleep(0.5)
        else:
            print(f"Tmux session '{session_name}' created. Attach with: tmux attach -t {session_name}")

    return TmuxProcess(session_name)
