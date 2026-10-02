# osv-scanner source scan

Run only through SourceScanner on the operator-bound repository. It stages bounded files,
uses fixed local/offline flags and caches by repository fingerprint. Do not route this
skill through the runtime ToolExecutor, which stores raw scanner output.
Never confirm runtime exploitation from an alert. Never use discovered credentials.
osv-scanner must be installed separately. Missing offline advisory databases produce an
honest unavailable result; dependency scanning falls back through the capability registry.
