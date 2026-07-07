#!/usr/bin/env python3
"""Test suite for the Log-to-CSV converter."""

import io
import json
import unittest
import server


class TestApacheParser(unittest.TestCase):
    """Test Apache access log parsing."""

    def setUp(self):
        self.sample = (
            '192.168.1.1 - - [10/Jul/2025:13:55:36 +0200] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"\n'
            '10.0.0.5 - frank [10/Jul/2025:13:56:01 +0200] "POST /api/data HTTP/1.1" 201 452 "-" "curl/7.68.0"\n'
            '172.16.0.1 - - [10/Jul/2025:13:56:45 +0200] "GET /style.css HTTP/1.1" 304 0 "-" "Mozilla/5.0"\n'
            '8.8.8.8 - - [10/Jul/2025:13:57:10 +0200] "DELETE /resource/42 HTTP/1.1" 404 178 "-" "python-requests"\n'
        )

    def test_parse_all_lines(self):
        result = server.parse_apache(self.sample)
        self.assertEqual(result["total_parsed"], 4)
        self.assertEqual(result["total_errors"], 0)
        self.assertEqual(len(result["rows"]), 4)
        self.assertEqual(len(result["columns"]), 11)

    def test_column_names(self):
        result = server.parse_apache(self.sample)
        self.assertIn("IP", result["columns"])
        self.assertIn("Metodo HTTP", result["columns"])
        self.assertIn("URL", result["columns"])
        self.assertIn("Data/Ora", result["columns"])
        self.assertIn("Codice Stato", result["columns"])

    def test_extract_ip(self):
        result = server.parse_apache(self.sample)
        self.assertEqual(result["rows"][0][0], "192.168.1.1")
        self.assertEqual(result["rows"][3][0], "8.8.8.8")

    def test_extract_method_and_url(self):
        result = server.parse_apache(self.sample)
        # Row 0: GET /index.html
        self.assertEqual(result["rows"][0][4], "GET")
        self.assertEqual(result["rows"][0][5], "/index.html")
        # Row 1: POST /api/data
        self.assertEqual(result["rows"][1][4], "POST")
        self.assertEqual(result["rows"][1][5], "/api/data")

    def test_extract_status_code(self):
        result = server.parse_apache(self.sample)
        self.assertEqual(result["rows"][0][7], "200")
        self.assertEqual(result["rows"][2][7], "304")
        self.assertEqual(result["rows"][3][7], "404")

    def test_parse_common_format(self):
        """Common Log Format (no referer/user-agent)."""
        log = '127.0.0.1 - - [01/Jan/2026:00:00:01 +0000] "GET / HTTP/1.0" 200 42'
        result = server.parse_apache(log)
        self.assertEqual(result["total_parsed"], 1)
        self.assertEqual(result["rows"][0][0], "127.0.0.1")
        self.assertEqual(result["rows"][0][4], "GET")
        self.assertEqual(result["rows"][0][5], "/")

    def test_empty_input(self):
        result = server.parse_apache("")
        self.assertEqual(result["total_parsed"], 0)
        self.assertEqual(result["total_errors"], 0)

    def test_unparseable_lines(self):
        log = "This is not an Apache log line\nAnother garbage line\n"
        result = server.parse_apache(log)
        self.assertEqual(result["total_parsed"], 0)
        self.assertEqual(result["total_errors"], 2)

    def test_mixed_lines(self):
        log = (
            '10.0.0.1 - - [10/Jul/2025:13:55:36 +0200] "GET / HTTP/1.1" 200 100\n'
            'garbage line\n'
            '10.0.0.2 - - [10/Jul/2025:13:56:00 +0200] "GET /about HTTP/1.1" 200 200\n'
        )
        result = server.parse_apache(log)
        self.assertEqual(result["total_parsed"], 2)
        self.assertEqual(result["total_errors"], 1)


class TestSyslogParser(unittest.TestCase):
    """Test Syslog (RFC 3164) parsing."""

    def setUp(self):
        self.sample = (
            "Jul 10 13:55:36 webserver sshd[1234]: Accepted publickey for admin from 192.168.1.100 port 22\n"
            "Jul 10 13:56:01 webserver kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.1 DST=10.0.0.2\n"
            "Jul 10 13:56:45 dbserver postgres: database ready for connections\n"
            "Jul 10 13:57:10 appserver myapp.py: INFO - Request processed in 42ms\n"
        )

    def test_parse_all_lines(self):
        result = server.parse_syslog(self.sample)
        self.assertEqual(result["total_parsed"], 4)
        self.assertEqual(result["total_errors"], 0)
        self.assertEqual(len(result["columns"]), 5)

    def test_column_names(self):
        result = server.parse_syslog(self.sample)
        self.assertIn("Data/Ora", result["columns"])
        self.assertIn("Hostname", result["columns"])
        self.assertIn("Processo", result["columns"])
        self.assertIn("Messaggio", result["columns"])

    def test_extract_hostname(self):
        result = server.parse_syslog(self.sample)
        self.assertEqual(result["rows"][0][1], "webserver")
        self.assertEqual(result["rows"][2][1], "dbserver")

    def test_extract_process(self):
        result = server.parse_syslog(self.sample)
        self.assertEqual(result["rows"][0][2], "sshd")
        self.assertEqual(result["rows"][1][2], "kernel")
        self.assertEqual(result["rows"][2][2], "postgres")

    def test_extract_pid(self):
        result = server.parse_syslog(self.sample)
        self.assertEqual(result["rows"][0][3], "1234")
        self.assertIsNone(result["rows"][1][3])  # kernel has no PID

    def test_extract_timestamp(self):
        result = server.parse_syslog(self.sample)
        self.assertEqual(result["rows"][0][0], "Jul 10 13:55:36")


class TestCustomParser(unittest.TestCase):
    """Test custom regex parsing."""

    def test_named_groups(self):
        log = 'ERROR 2025-07-10 Database connection failed\nINFO  2025-07-10 Server started'
        pattern = r'(?P<livello>\w+)\s+(?P<data>\d{4}-\d{2}-\d{2})\s+(?P<messaggio>.+)'
        result = server.parse_custom(log, pattern)
        self.assertEqual(result["total_parsed"], 2)
        self.assertEqual(result["columns"], ["livello", "data", "messaggio"])
        self.assertEqual(result["rows"][0], ["ERROR", "2025-07-10", "Database connection failed"])

    def test_unnamed_groups(self):
        log = 'alpha 123 beta\ngamma 456 delta'
        pattern = r'(\w+)\s+(\d+)\s+(\w+)'
        result = server.parse_custom(log, pattern)
        self.assertEqual(result["total_parsed"], 2)
        self.assertEqual(result["columns"], ["Col_1", "Col_2", "Col_3"])
        self.assertEqual(result["rows"][0], ["alpha", "123", "beta"])

    def test_invalid_regex(self):
        result = server.parse_custom("any text", r'[invalid')
        self.assertIn("error", result)

    def test_no_matches(self):
        result = server.parse_custom("hello world", r'\d+')
        self.assertEqual(result["total_parsed"], 0)
        self.assertEqual(result["total_errors"], 1)

    def test_search_vs_match(self):
        """Regex uses search(), so it matches anywhere in the line."""
        log = 'prefix ERROR 2025-07-10 message suffix'
        pattern = r'(?P<livello>ERROR)\s+(?P<data>\d{4}-\d{2}-\d{2})\s+(?P<messaggio>message)'
        result = server.parse_custom(log, pattern)
        self.assertEqual(result["total_parsed"], 1)


class TestCSVBuilder(unittest.TestCase):
    """Test CSV output generation."""

    def test_basic_csv(self):
        columns = ["Nome", "Età", "Città"]
        rows = [
            ["Alice", "30", "Roma"],
            ["Bob", "25", "Milano"],
        ]
        csv_str = server.build_csv(columns, rows)
        lines = csv_str.strip().split("\r\n")
        self.assertEqual(lines[0], "Nome,Età,Città")
        self.assertEqual(lines[1], "Alice,30,Roma")
        self.assertEqual(lines[2], "Bob,25,Milano")

    def test_empty_rows(self):
        csv_str = server.build_csv(["Col1"], [])
        self.assertEqual(csv_str.strip(), "Col1")

    def test_special_characters(self):
        columns = ["Campo"]
        rows = [['valore con "virgolette" e , virgola']]
        csv_str = server.build_csv(columns, rows)
        self.assertIn('"valore con ""virgolette"" e , virgola"', csv_str)


class TestServerEndpoints(unittest.TestCase):
    """Test Flask server endpoints."""

    def setUp(self):
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()

    def test_index_returns_html(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"<!DOCTYPE html>", resp.data)

    def test_robots_txt(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"User-agent", resp.data)

    def test_sitemap_xml(self):
        resp = self.client.get("/sitemap.xml")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"<urlset", resp.data)

    def test_parse_no_file(self):
        resp = self.client.post("/api/parse")
        self.assertEqual(resp.status_code, 400)
        data = json.loads(resp.data)
        self.assertIn("error", data)

    def test_parse_empty_filename(self):
        data = {"file": (io.BytesIO(b""), "")}
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_parse_apache(self):
        log = '192.168.1.1 - - [10/Jul/2025:13:55:36 +0200] "GET /index.html HTTP/1.1" 200 2326'
        data = {
            "file": (io.BytesIO(log.encode()), "test.log"),
            "format": "apache",
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        result = json.loads(resp.data)
        self.assertEqual(result["total_parsed"], 1)
        self.assertEqual(result["rows"][0][0], "192.168.1.1")
        self.assertEqual(result["rows"][0][4], "GET")
        self.assertEqual(result["rows"][0][5], "/index.html")

    def test_parse_syslog(self):
        log = "Jul 10 13:55:36 webserver sshd[1234]: Accepted publickey"
        data = {
            "file": (io.BytesIO(log.encode()), "syslog.log"),
            "format": "syslog",
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        result = json.loads(resp.data)
        self.assertEqual(result["total_parsed"], 1)
        self.assertEqual(result["rows"][0][1], "webserver")

    def test_parse_custom_with_regex(self):
        log = "ERROR 2025-07-10 Something broke"
        pattern = r'(?P<level>\w+)\s+(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<msg>.+)'
        data = {
            "file": (io.BytesIO(log.encode()), "custom.log"),
            "format": "custom",
            "regex": pattern,
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        result = json.loads(resp.data)
        self.assertEqual(result["total_parsed"], 1)
        self.assertEqual(result["columns"], ["level", "date", "msg"])

    def test_parse_custom_no_regex(self):
        log = "some data"
        data = {
            "file": (io.BytesIO(log.encode()), "custom.log"),
            "format": "custom",
            "regex": "",
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_parse_unsupported_format(self):
        log = "data"
        data = {
            "file": (io.BytesIO(log.encode()), "test.log"),
            "format": "json",
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_download_apache_csv(self):
        log = '192.168.1.1 - - [10/Jul/2025:13:55:36 +0200] "GET /index.html HTTP/1.1" 200 2326'
        data = {
            "file": (io.BytesIO(log.encode()), "test.log"),
            "format": "apache",
        }
        resp = self.client.post("/api/download", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertIn("log_convertito.csv", resp.headers.get("Content-Disposition", ""))
        # Verify CSV content
        csv_text = resp.data.decode("utf-8-sig")
        self.assertIn("IP", csv_text)
        self.assertIn("192.168.1.1", csv_text)

    def test_download_syslog_csv(self):
        log = "Jul 10 13:55:36 webserver sshd[1234]: Accepted publickey"
        data = {
            "file": (io.BytesIO(log.encode()), "syslog.log"),
            "format": "syslog",
        }
        resp = self.client.post("/api/download", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        csv_text = resp.data.decode("utf-8-sig")
        self.assertIn("Hostname", csv_text)
        self.assertIn("webserver", csv_text)

    def test_parse_empty_file(self):
        data = {
            "file": (io.BytesIO(b"   \n\n"), "empty.log"),
            "format": "apache",
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_csv_filename_is_correct(self):
        """Criterion: downloaded CSV must be named log_convertito.csv."""
        log = '127.0.0.1 - - [01/Jan/2026:00:00:01 +0000] "GET / HTTP/1.0" 200 42'
        data = {
            "file": (io.BytesIO(log.encode()), "access.log"),
            "format": "apache",
        }
        resp = self.client.post("/api/download", data=data, content_type="multipart/form-data")
        cd = resp.headers.get("Content-Disposition", "")
        self.assertIn("log_convertito.csv", cd)

    def test_minimum_four_columns_for_apache(self):
        """Criterion: Apache log must produce at least 4 columns (IP, data, HTTP method, URL)."""
        log = '192.168.1.1 - - [10/Jul/2025:13:55:36 +0200] "GET /index.html HTTP/1.1" 200 2326'
        data = {
            "file": (io.BytesIO(log.encode()), "test.log"),
            "format": "apache",
        }
        resp = self.client.post("/api/parse", data=data, content_type="multipart/form-data")
        result = json.loads(resp.data)
        self.assertGreaterEqual(len(result["columns"]), 4)
        # Verify the 4 key columns are present
        self.assertIn("IP", result["columns"])
        self.assertIn("Data/Ora", result["columns"])
        self.assertIn("Metodo HTTP", result["columns"])
        self.assertIn("URL", result["columns"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
