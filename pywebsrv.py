"""
License:
     PyWebServer
     Copyright (C) 2025 Nova

     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

     You should have received a copy of the GNU General Public License along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Contact:
        E-mail: nova@novacow.ch

NOTE: Once 2.0 is released, PyWebServer will become the Amethyst Web Server

This is PyWebServer, an ultra minimalist webserver, meant to still have
a lot standard webserver features. A comprehensive list is below:
Features:
HTTP and HTTPS support.
Automatically generate certificates using AutoCertGen plugin.
Blocking per host.
Easy port configuration.
Easy to understand documentation and configuration.
Very small size, compared to something like Apache and NGINX.
No compromise(-ish) security:
    Directory traversal attack prevention.
    No fuss HTTPS setup.
    Per-host blocking.
    Ability for per-IP blocking.
    Ability for per-UA blocking.
Simple to understand and mod codebase.
All GNU GPL-3-or-above license. (Do with it what you want.)
Library aswell as a standalone script:
    You can easily get access to other parts of the script if you need it.

TODO: actually put normal comments in
"""

import os
import mimetypes
import threading
import ssl
import socket
import re
import signal
import sys

try:
    from certgen import AutoCertGen
except ImportError:
    # just do nothing, it's not working anyway.
    # print(
    #     "WARN: You need the AutoCertGen plugin! Please install it from\n"
    #     "https://git.novacow.ch/Nova/AutoCertGen/"
    # )
    pass


class FileHandler:
    CONFIG_FILE = "pywebsrv.conf"

    def __init__(self, base_dir=None):
        self.config_path = os.path.join(os.getcwd(), self.CONFIG_FILE)
        self.base_dir = self.read_config("directory")
        self.cached_conf = None
        if not os.path.exists(self.config_path):
            print(
                "The pywebsrv.conf file needs to be in the same directory "
                "as pywebsrv.py! Get the default config file from:\n"
                "https://git.novacow.ch/Nova/PyWebServer/raw/branch/main/pywebsrv.conf"
            )
            exit(1)

    def read_file(self, file_path):
        if "../" in file_path:
            return 403, None

        full_path = os.path.join(self.base_dir, file_path.lstrip("/"))
        if not os.path.isfile(full_path):
            return 404, None

        try:
            mimetype = mimetypes.guess_type(full_path)
            with open(full_path, "rb") as f:
                return f.read(), mimetype
        except Exception as e:
            print(f"Error reading file {full_path}: {e}")
            return 500, None

    def write_file(self, file_path, data):
        if "../" in file_path:
            return 403
        full_path = os.path.join(self.base_dir, file_path.lstrip("/"))
        with open(full_path, "a") as f:
            f.write(data)
        return 0

    def read_config(self, option):
        """
        clean code, whats that????
        TODO: docs
        """
        option = option.lower()
        valid_options = [
            "port",
            "directory",
            "host",
            "http",
            "https",
            "port-https",
            "allow-localhost",
            "disable-autocertgen",
            "key-file",
            "cert-file",
            "block-ua"
        ]
        if option not in valid_options:
            return None
        with open(self.config_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                try:
                    key, value = line.strip().split(":", 1)
                except ValueError:
                    return None
                key = key.lower()
                if key == option:
                    if option == "host":
                        seperated_values = value.split(",", -1)
                        return [value.lower() for value in seperated_values]
                    if option == "block-ua":
                        seperated_values = value.split(",", -1)
                        host_to_match = []
                        literal_blocks = []
                        for val in seperated_values:
                            if val.startswith("match(") and val.endswith(")"):
                                idx = val.index("(")
                                idx2 = val.index(")")
                                ua_to_match = val[idx+1:idx2]
                                host_to_match.append(ua_to_match)
                            else:
                                literal_blocks.append(val)
                        return host_to_match, literal_blocks
                    if option == "port" or option == "port-https":
                        return int(value)
                    if (
                        option == "http"
                        or option == "https"
                        or option == "allow-localhost"
                        or option == "disable-autocertgen"
                    ):
                        return bool(int(value))
                    if option == "directory":
                        if value == "<Enter directory here>":
                            return os.path.join(os.getcwd(), "html")
                        if value.endswith("/"):
                            value = value.rstrip("/")
                        return value
                    return value
        if option == "block-ua":
            return [], []
        return None

    def read_new_config(self, option, host=None):
        """
        Reads the configuration file and returns a dict
        """
        if self.cached_conf is None:
            with open(self.config_path, "r", encoding="utf-8") as fh:
                text = fh.read()

            blocks = re.findall(
                r'^(host\s+(\S+)|globals)\s*\{([^}]*)\}', text, re.MULTILINE
            )
            parsed = {}
            host_list = []
            for tag, hostname, body in blocks:
                section = hostname if hostname else "globals"
                if hostname:
                    host_list.append(hostname)
                kv = {}
                for line in body.splitlines():
                    line = line.strip()
                    if not line or ":" not in line or line.starswith("#"):
                        continue

                    key, rest = line.split(":", 1)
                    key = key.strip()
                    rest = rest.strip()

                    # Split comma-separated values (e.g. GET,PUT)
                    if "," in rest:
                        kv[key] = [item.strip() for item in rest.split(",")]
                    else:
                        kv[key] = rest
                parsed[section] = kv
                parsed["globals"]["hosts"] = host_list
                self.cached_conf = parsed
            else:
                parsed = self.cached_conf
            if option == "host":
                try:
                    return host_list
                except Exception:
                    return parsed["globals"]["hosts"]
            section = parsed.get(host or "globals", {})
            return section.get(option)

    def autocert(self):
        """
        Generate some self-signed certificates using AutoCertGen
        TODO: doesn't work, need to fix. probably add `./` to $PATH
        """
        autocert = AutoCertGen()
        autocert.gen_cert()


class RequestParser:
    def __init__(self):
        self.file_handler = FileHandler()
        self.hosts = self.file_handler.read_config("host")

    def parse_request_line(self, line):
        """Parses the HTTP request line."""
        try:
            method, path, version = line.split(" ")
        except ValueError:
            return None, None, None
        if path.endswith("/"):
            path += "index.html"
        return method, path, version

    def ua_blocker(self, ua):
        """Parses and matches UA to block"""
        match, literal = self.file_handler.read_config("block-ua")
        if ua in literal:
            return False
        for _ua in match:
            if _ua.lower() in ua.lower():
                return False
        return True

    def is_method_allowed(self, method):
        """
        Checks if the HTTP method is allowed.
        Reads allowed methods from a configuration file.
        Falls back to allowing only 'GET' if the file does not exist.
        Should (for now) only be GET as I haven't implemented the logic for PUT
        """
        allowed_methods = ["GET"]
        # While the logic for PUT, DELETE, etc. is not added, we shouldn't
        # allow for it to attempt it.
        # Prepatched for new update.
        # allowed_methods = self.file_handler.read_config("allowed-methods")
        return method in allowed_methods

    def host_parser(self, host):
        """
        Parses the host and makes sure it's allowed in
        Mfw im in an ugly code writing contest and my opponent is nova while writing a side project
        """
        host = f"{host}"
        if ":" in host:
            host = host.split(":", 1)[0]
        host = host.lstrip()
        host = host.rstrip()
        if (
            host == "localhost" or host == "127.0.0.1"
        ) and self.file_handler.read_config("allow-localhost"):
            return True
        if host not in self.hosts:
            return False
        else:
            return True

#
# class ProxyServer:
#     def __init__(
#         self,
#     ):


class WebServer:
    def __init__(
        self, http_port=8080, https_port=8443, cert_file="cert.pem", key_file="key.pem"
    ):
        self.http_port = http_port
        self.https_port = https_port
        self.cert_file = cert_file
        self.key_file = key_file
        self.file_handler = FileHandler()
        self.parser = RequestParser()
        self.skip_ssl = False

        # me when no certificate and key file
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            if not os.path.exists(self.cert_file) and not os.path.exists(self.key_file):
                pass
            # maybe warn users we purge their key/cert files? xdd
            elif not os.path.exists(self.cert_file):
                os.remove(self.key_file)
            elif not os.path.exists(self.key_file):
                os.remove(self.cert_file)
            print("WARN: No HTTPS certificate was found!")
            if self.file_handler.read_config("disable-autocertgen") is True:
                print("WARN: AutoCertGen is disabled, ignoring...")
                self.skip_ssl = True
            else:
                choice = input("Do you wish to generate an HTTPS certificate? [y/N] ")
                if choice.lower() == "y":
                    self.file_handler.autocert()
                else:
                    self.skip_ssl = True

        self.no_host_req_response = (
            "This host cannot be reached without sending a `Host` header."
        )

        # ipv6 when????/??//?????//?
        self.http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.http_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.http_socket.bind(("0.0.0.0", self.http_port))

        self.https_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.https_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.https_socket.bind(("0.0.0.0", self.https_port))

        if self.skip_ssl is False:
            # https gets the ssl treatment!! yaaaay :3
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                certfile=self.cert_file, keyfile=self.key_file
            )
            self.https_socket = self.ssl_context.wrap_socket(
                self.https_socket, server_side=True
            )

        self.http_404_html = (
            "<html><head><title>HTTP 404 - PyWebServer</title></head>"
            "<body><center><h1>HTTP 404 - Not Found!</h1><p>Running PyWebServer/1.2.1</p>"
            "</center></body></html>"
        )
        self.http_403_html = (
            "<html><head><title>HTTP 403 - PyWebServer</title></head>"
            "<body><center><h1>HTTP 403 - Forbidden</h1><p>Running PyWebServer/1.2.1</p>"
            "</center></body></html>"
        )
        self.http_405_html = (
            "<html><head><title>HTTP 405 - PyWebServer</title></head>"
            "<body><center><h1>HTTP 405 - Method not allowed</h1><p>Running PyWebServer/1.2.1</p>"
            "</center></body></html>"
        )

        self.running = True

    def start(self, http, https):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        http_thread = threading.Thread(target=self.start_http, daemon=True)
        https_thread = threading.Thread(target=self.start_https, daemon=True)

        if https is True:
            if self.skip_ssl is True:
                print("WARN: You have enabled HTTPS without SSL!!")
                yn = input("Is this intended behaviour? [y/N] ")
            https_thread.start()
        if http is True:
            http_thread.start()

        http_thread.join()
        https_thread.join()

    def start_http(self):
        self.http_socket.listen(5)
        print(f"HTTP server listening on port {self.http_port}...")
        while self.running:
            try:
                conn, addr = self.http_socket.accept()
                self.handle_connection(conn, addr)
            except Exception as e:
                print(f"HTTP error: {e}")
            except OSError:
                break

    def start_https(self):
        self.https_socket.listen(5)
        print(f"HTTPS server listening on port {self.https_port}...")
        while self.running:
            try:
                conn, addr = self.https_socket.accept()
                self.handle_connection(conn, addr)
            except Exception as e:
                print(
                    f"HTTPS error: {e}"
                )  # be ready for ssl errors if you use a self-sign!!
            except OSError:
                break

    def handle_connection(self, conn, addr):
        try:
            data = conn.recv(512)
            request = data.decode(errors="ignore")
            if not data:
                response = self.build_response(400, "Bad Request")  # user did fucky-wucky
            elif len(data) > 8192:
                response = self.build_response(413, "Request too long")
            else:
                response = self.handle_request(request, addr)

            if isinstance(response, str):
                response = response.encode()

            conn.sendall(response)
        except Exception as e:
            print(f"Error handling connection: {e}")
        finally:
            conn.close()

    def handle_request(self, data, addr):
        print(f"data: {data}")
        request_line = data.splitlines()[0]

        # Extract host from headers, never works though
        for line in data.splitlines():
            if "Host" in line:
                host = line.split(":", 1)[1].strip()
                allowed = self.parser.host_parser(host)
                if not allowed:
                    return self.build_response(
                        403, "Connecting via this host is disallowed."
                    )
                break
        else:
            return self.build_response(
                400, self.no_host_req_response.encode()
            )

        for line in data.splitlines():
            if "User-Agent" in line:
                ua = line.split(":", 1)[1].strip()
                allowed = self.parser.ua_blocker(ua)
                if not allowed:
                    return self.build_response(
                        403, "This UA has been blocked by the owner of this site."
                    )
                break
        else:
            return self.build_response(
                400, "You cannot connect without a User-Agent."
            )

        method, path, version = self.parser.parse_request_line(request_line)

        if not all([method, path, version]):
            return self.build_response(400, "Bad Request")

        # Figure out a better way to reload config
        if path == "/?pywebsrv_reload_conf=1":
            print("Got reload command! Reloading configuration...")
            self.file_handler = FileHandler()
            self.parser = RequestParser()
            return self.build_response(302, "")

        if not self.parser.is_method_allowed(
            method
        ):
            return self.build_response(405, self.http_405_html)

        file_content, mimetype = self.file_handler.read_file(path)

        if file_content == 403:
            print("WARN: Directory traversal attack prevented.")  # look ma, security!!
            return self.build_response(403, self.http_403_html)
        if file_content == 404:
            return self.build_response(404, self.http_404_html)
        if file_content == 500:
            return self.build_response(
                500,
                "PyWebServer has encountered a fatal error and cannot serve "
                "your request. Contact the owner with this error: FATAL_FILE_RO_ACCESS",
            )  # When there was an issue with reading we throw this.

        # A really crude implementation of binary files. Later in 2.0 I'll actually
        # make this useful.
        mimetype = mimetype[0]
        if mimetype is None:
            # We have to assume it's binary.
            return self.build_binary_response(200, file_content, "application/octet-stream")
        if "text/" not in mimetype:
            return self.build_binary_response(200, file_content, mimetype)

        return self.build_response(200, file_content)

    @staticmethod
    def build_binary_response(status_code, binary_data, content_type):
        """Handles binary files like MP3s."""
        messages = {
            200: "OK",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error"
        }
        status_message = messages.get(status_code)
        headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Server: PyWebServer/1.4\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(binary_data)}\r\n"
            f"Connection: close\r\n\r\n"
            # Connection close is done because it is way easier to implement.
            # It's not like this program will see production use anyway.
            # Tbh when i'll implement HTTP2
        )
        return headers.encode() + binary_data

    def build_response(self, status_code, body):
        """
        For textfiles we'll not have to guess MIME-types, though the other function
        build_binary_response will be merged in here anyway.
        """
        messages = {
            200: "OK",
            204: "No Content",
            302: "Found",
            304: "Not Modified",  # TODO KEKL
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            413: "Payload Too Large",
            500: "Internal Server Error",
            635: "Go Away"
        }
        status_message = messages.get(status_code)

        if isinstance(body, str):
            body = body.encode()

        # TODO: dont encode yet, and i encode. awesome comments here.
        # Don't encode yet, if 302 status code we have to include location.
        headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Server: PyWebServer/1.4\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        if status_code == 302:
            # 302 currently only happens when the reload is triggered.
            # Why not 307, Moved Permanently? Because browsers will cache the
            # response and not send the reload command.
            host = self.file_handler.read_config("host")[0]
            port = self.file_handler.read_config("port-https") or self.file_handler.read_config("port")
            if port != 80 and port != 443:
                if port == 8443:
                    host = f"https://{host}:{port}/"
                else:
                    host = f"http://{host}:{port}/"
            else:
                if port == 443:
                    host = f"https://{host}/"
                else:
                    host = f"http://{host}/"
            headers = (
                f"HTTP/1.1 {status_code} {status_message}\r\n"
                f"Location: {host}\r\n"
                f"Server: PyWebServer/1.2.1\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

        return headers + body

    def shutdown(self, signum, frame):
        print("\nRecieved signal to exit!\nShutting down server...")
        self.running = False
        self.http_socket.close()
        self.https_socket.close()
        sys.exit(0)


def main():
    file_handler = FileHandler()
    # file_handler.check_first_run()
    file_handler.base_dir = file_handler.read_config("directory")
    http_port = file_handler.read_config("port") or 8080
    https_port = file_handler.read_config("port-https") or 8443
    http_enabled = file_handler.read_config("http") or True
    https_enabled = file_handler.read_config("https") or False
    server = WebServer(http_port=http_port, https_port=https_port)
    server.start(http_enabled, https_enabled)


if __name__ == "__main__":
    main()
