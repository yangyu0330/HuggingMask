class DemoModel:
    def forward(self, user_path):
        with open(user_path, "r") as handle:
            return handle.read()
