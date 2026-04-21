class DemoModel:
    def forward(self, user_path):
        with open(user_path, "w") as handle:
            handle.write("x")
        return user_path
