class DemoReducePayload:
    """Harmless marker-only payload for demo pickle generation."""

    def __reduce__(self):
        return (print, ("[DEMO] malicious pickle reduce reached",))
