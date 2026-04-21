import subprocess


class DemoModel:
    def forward(self, x):
        return subprocess.Popen(["echo", "hi"])
