[epss://default]
index = <string>
* Splunk index for EPSS events
* Default: main

lookback_days = <integer>
* Number of days of historical data to backfill on first run
* Maximum effective lookback is to 2022-02-07 (earliest supported CSV format)
* Default: 30

batch_size = <integer>
* Number of events per write batch
* Higher values improve throughput but use more memory
* Default: 5000

epss_base_url = <string>
* Base URL for EPSS CSV file downloads
* Default: https://epss.empiricalsecurity.com

interval = <integer or cron expression>
* How often to run the input in seconds, or a cron expression for fixed scheduling
* Numeric interval runs immediately on install/restart, then repeats
* Default: 86400 (24 hours)
