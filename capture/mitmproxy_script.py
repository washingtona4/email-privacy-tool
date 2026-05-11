import csv
import os
from datetime import datetime

from mitmproxy import http


class EmailPrivacyLogger:
    def __init__(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(os.environ.get('OUTPUT_DIR', 'output'), exist_ok=True)
        self.csv_path = f"{os.environ.get('OUTPUT_DIR', 'output')}/capture_{timestamp}.csv"
        self.columns = [
            "timestamp",
            "method",
            "host",
            "path",
            "request_size",
            "response_size",
            "content_type",
            "status_code",
            "request_headers",
            "request_body_snippet",
            "response_headers",
            "set_cookies",
        ]
        # row lookup so response hook can update the same row
        self._rows: dict[str, dict] = {}

        with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.columns)
            writer.writeheader()
            f.flush()

    # ------------------------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        body_raw = req.content or b""
        body_snippet = body_raw[:500].decode("utf-8", errors="replace")

        row = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": req.method,
            "host": req.pretty_host,
            "path": req.path,
            "request_size": len(body_raw),
            "response_size": "",
            "content_type": req.headers.get("content-type", ""),
            "status_code": "",
            "request_headers": dict(req.headers),
            "request_body_snippet": body_snippet,
            "response_headers": "",
            "set_cookies": "",
        }
        self._rows[flow.id] = row
        self._append_row(row)

    # ------------------------------------------------------------------
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.id not in self._rows:
            return

        resp = flow.response
        body_raw = resp.content or b""

        row = self._rows.pop(flow.id)
        row["response_size"] = len(body_raw)
        row["content_type"] = resp.headers.get("content-type", row["content_type"])
        row["status_code"] = resp.status_code
        row["response_headers"] = dict(resp.headers)
        row["set_cookies"] = resp.headers.get("set-cookie", "")

        # Rewrite the whole file is expensive; append an update row instead.
        # Downstream analysis should use the last row per (timestamp, host, path).
        self._append_row(row)

    # ------------------------------------------------------------------
    def _append_row(self, row: dict) -> None:
        with open(self.csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.columns)
            writer.writerow(row)
            f.flush()


addons = [EmailPrivacyLogger()]
