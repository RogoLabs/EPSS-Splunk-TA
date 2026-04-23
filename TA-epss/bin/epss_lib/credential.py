import logging
from typing import Optional

try:
    import splunklib.client as client
except ImportError:
    client = None


class CredentialManager:
    REALM = "TA-epss"

    def __init__(
        self,
        session_key: str,
        splunk_uri: str = "https://localhost:8089",
        app: str = "TA-epss",
        logger: Optional[logging.Logger] = None,
    ):
        self.session_key = session_key
        self.splunk_uri = splunk_uri
        self.app = app
        self.logger = logger or logging.getLogger("ta_epss.credential")
        self._service = None

    @property
    def service(self):
        if self._service is None:
            if client is None:
                raise ImportError("splunklib is required for credential management")
            from urllib.parse import urlparse

            parsed = urlparse(self.splunk_uri)
            self._service = client.connect(
                token=self.session_key,
                host=parsed.hostname or "localhost",
                port=parsed.port or 8089,
                app=self.app,
                autologin=True,
            )
        return self._service

    def get_proxy_config(self) -> Optional[dict]:
        try:
            for credential in self.service.storage_passwords:
                if credential.realm == self.REALM:
                    self.logger.debug("Proxy config retrieved from secure storage")
                    return {"https": credential.clear_password}
            self.logger.info("No proxy configured - using direct connection")
            return None
        except Exception as e:
            self.logger.warning(f"Could not retrieve proxy config: {e}")
            return None
