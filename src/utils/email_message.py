class EmailMessage:
    def __init__(self, raw_email_text: str):
        self._raw_email_text = raw_email_text

    def to_bytes(self) -> bytes:
        return self._raw_email_text.encode("utf-8")