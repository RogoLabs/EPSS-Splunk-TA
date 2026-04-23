#!/usr/bin/env python3
import sys

if __name__ == "__main__" and "--scheme" in sys.argv:
    sys.stdout.write("""<scheme>
    <title>epss</title>
    <description>Ingests daily EPSS scores from FIRST</description>
    <use_external_validation>false</use_external_validation>
    <use_single_instance>false</use_single_instance>
    <streaming_mode>xml</streaming_mode>
    <endpoint>
        <args>
            <arg name="index">
                <title>Index</title>
                <description>Splunk index for EPSS events</description>
                <required_on_create>false</required_on_create>
                <data_type>string</data_type>
            </arg>
            <arg name="lookback_days">
                <title>Lookback Days</title>
                <description>Days of historical data to backfill on first run</description>
                <required_on_create>false</required_on_create>
                <data_type>number</data_type>
            </arg>
            <arg name="batch_size">
                <title>Batch Size</title>
                <description>Number of events per write batch</description>
                <required_on_create>false</required_on_create>
                <data_type>number</data_type>
            </arg>
            <arg name="epss_base_url">
                <title>EPSS Base URL</title>
                <description>Base URL for EPSS CSV downloads</description>
                <required_on_create>false</required_on_create>
                <data_type>string</data_type>
            </arg>
        </args>
    </endpoint>
</scheme>""")
    sys.stdout.flush()
    sys.exit(0)

import json
import os
import time
import traceback
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
sys.path.insert(0, os.path.dirname(__file__))

try:
    from epss_lib.checkpoint import CheckpointManager
    from epss_lib.credential import CredentialManager
    from epss_lib.csv_processor import get_stats, parse_csv
    from epss_lib.epss_client import EPSSClient, EPSSDownloadError, EPSSNotAvailable
    from epss_lib.logging_config import setup_logging
    from splunklib.modularinput import Argument, Event, EventWriter, Scheme, Script
except (ImportError, OSError) as e:
    sys.stderr.write(f"ERROR TA-epss: Failed to import: {e}\n")
    sys.exit(1)


class EPSSInput(Script):
    APP_NAME = "TA-epss"

    def __init__(self):
        super().__init__()
        self.logger = None

    def get_scheme(self) -> Scheme:
        scheme = Scheme("epss")
        scheme.description = "Ingests daily EPSS scores from FIRST"
        scheme.use_external_validation = False
        scheme.streaming_mode = Scheme.streaming_mode_xml
        scheme.use_single_instance = False

        arg = Argument("index")
        arg.title = "Index"
        arg.data_type = Argument.data_type_string
        arg.required_on_create = False
        scheme.add_argument(arg)

        arg = Argument("lookback_days")
        arg.title = "Lookback Days"
        arg.data_type = Argument.data_type_number
        arg.required_on_create = False
        scheme.add_argument(arg)

        arg = Argument("batch_size")
        arg.title = "Batch Size"
        arg.data_type = Argument.data_type_number
        arg.required_on_create = False
        scheme.add_argument(arg)

        arg = Argument("epss_base_url")
        arg.title = "EPSS Base URL"
        arg.data_type = Argument.data_type_string
        arg.required_on_create = False
        scheme.add_argument(arg)

        return scheme

    def validate_input(self, validation_definition):
        pass

    def stream_events(self, inputs, ew: EventWriter) -> None:
        self.logger = setup_logging("INFO")
        self.logger.info("EPSS modular input starting")

        server_uri = inputs.metadata.get("server_uri", "https://localhost:8089")
        session_key = inputs.metadata.get("session_key")

        if not session_key:
            self.logger.error("No session key available")
            return

        for input_name, input_config in inputs.inputs.items():
            try:
                self._process_input(input_name, input_config, server_uri, session_key, ew)
            except Exception as e:
                self.logger.error(f"Fatal error processing {input_name}: {e}")
                self.logger.error(traceback.format_exc())
                self._write_audit_event(
                    ew, "error", input_config.get("index", "main"), error=str(e)
                )

    def _process_input(self, input_name, input_config, server_uri, session_key, ew):
        index = input_config.get("index", "main")
        lookback_days = int(input_config.get("lookback_days", "30"))
        batch_size = int(input_config.get("batch_size", "5000"))
        base_url = input_config.get("epss_base_url", "https://epss.empiricalsecurity.com")

        self._write_audit_event(ew, "input_started", index)

        cred_manager = CredentialManager(
            session_key=session_key, splunk_uri=server_uri, logger=self.logger
        )
        proxies = cred_manager.get_proxy_config()

        client = EPSSClient(base_url=base_url, proxies=proxies)

        from urllib.parse import urlparse

        from splunklib.client import connect as splunk_connect

        parsed = urlparse(server_uri)
        service = splunk_connect(
            token=session_key,
            host=parsed.hostname or "localhost",
            port=parsed.port or 8089,
            app=self.APP_NAME,
            autologin=True,
        )

        checkpoint_mgr = CheckpointManager(service=service, logger=self.logger)
        checkpoint_mgr.get_checkpoint()

        dates = checkpoint_mgr.get_dates_to_process(lookback_days=lookback_days)
        if not dates:
            self.logger.info("No new dates to process - already up to date")
            self._write_audit_event(ew, "input_complete", index, message="Already up to date")
            return

        self.logger.info(f"Processing {len(dates)} date(s): {dates[0]} to {dates[-1]}")
        start_time = time.time()

        for i, score_date in enumerate(dates):
            try:
                self._write_audit_event(ew, "download_started", index, score_date=score_date)

                csv_content = client.download_scores(score_date)
                file_size = len(csv_content.encode("utf-8"))

                self._write_audit_event(
                    ew, "download_complete", index, score_date=score_date, file_size_bytes=file_size
                )

                records = parse_csv(csv_content, fallback_date=score_date)
                stats = get_stats()

                self._write_events_batched(records, batch_size, ew, index, input_name)

                duration = time.time() - start_time
                self._write_audit_event(
                    ew,
                    "ingest_complete",
                    index,
                    score_date=score_date,
                    records_ingested=stats["parsed"],
                    duration_seconds=round(duration, 1),
                    http_status=200,
                    file_size_bytes=file_size,
                )

                checkpoint_mgr.save_checkpoint(
                    date_ingested=score_date,
                    records_processed=stats["parsed"],
                )

                if i < len(dates) - 1:
                    time.sleep(1)

            except EPSSNotAvailable:
                self.logger.warning(f"EPSS data not available for {score_date}, skipping")
                continue
            except EPSSDownloadError as e:
                self.logger.error(f"Download failed for {score_date}: {e}")
                checkpoint_mgr.save_checkpoint(error=str(e))
                self._write_audit_event(ew, "error", index, score_date=score_date, error=str(e))
                continue

        total_duration = time.time() - start_time
        self._write_audit_event(
            ew,
            "input_complete",
            index,
            dates_processed=len(dates),
            duration_seconds=round(total_duration, 1),
        )
        self.logger.info(f"EPSS input complete: {len(dates)} dates in {total_duration:.1f}s")

    def _write_events_batched(self, records, batch_size, ew, index, input_name):
        for i in range(0, len(records), batch_size):
            batch = records[i : i + batch_size]
            self._write_batch(batch, ew, index, input_name)

    def _write_batch(self, records, ew, index, input_name):
        for record in records:
            try:
                event = Event()
                event.stanza = input_name
                event.sourceType = "epss:score"
                event.source = "epss"
                event.index = index
                event.host = "epss"
                event.data = json.dumps(record, separators=(",", ":"))
                ew.write_event(event)
            except Exception as e:
                self.logger.error(f"Error writing event for {record.get('cve_id', '?')}: {e}")

    def _write_audit_event(self, ew, action, index, **kwargs):
        try:
            data = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "action": action,
            }
            data.update(kwargs)
            event = Event()
            event.sourceType = "epss:audit"
            event.source = "epss"
            event.index = index
            event.host = "epss"
            event.data = json.dumps(data, separators=(",", ":"))
            ew.write_event(event)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(EPSSInput().run(sys.argv))
