"""
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
"""

import os
import threading
import ssl
import socket
import signal
import sys

try:
    from autocertgen import AutoCertGen
except ImportError:
    print(
        "WARN: You need the AutoCertGen plugin! Please install it from\n"
        "https://git.novacow.ch/Nova/AutoCertGen/"
    )


class FileHandler:
    CONFIG_FILE = "pywebsrv.conf"
    DEFAULT_CONFIG = (
        "port:8080\nport-https:8443\nhttp:1"
        "\nhttps:0\ndirectory:{cwd}\nhost:localhost"
        "allow-all:1\nallow-localhost:1"
    )

    def __init__(self, base_dir=None):
        self.config_path = os.path.join(os.getcwd(), self.CONFIG_FILE)
        self.base_dir = self.read_config("directory")

    def check_first_run(self):
        if not os.path.isfile(self.config_path):
            self.on_first_run()
            return True
        return False

    def on_first_run(self):
        with open(self.config_path, "w") as f:
            f.write(self.DEFAULT_CONFIG.format(cwd=os.getcwd()))

    def read_file(self, file_path):
        if "../" in file_path:
            return 403

        full_path = os.path.join(self.base_dir, file_path.lstrip("/"))
        if not os.path.isfile(full_path):
            return 404

        try:
            with open(full_path, "rb") as f:
                return f.read()
        except Exception as e:
            print(f"Error reading file {full_path}: {e}")
            return 500

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
            "allow-all",
            "allow-nohost",
            "allow-localhost",
            "disable-autocertgen",
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
                        seperated_values = value.split(",", 0)
                        return [value.lower() for value in seperated_values]
                    if option == "port" or option == "port-https":
                        return int(value)
                    if (
                        option == "http"
                        or option == "https"
                        or option == "allow-all"
                        or option == "allow-localhost"
                        or option == "disable-autocertgen"
                        or option == "allow-nohost"
                    ):
                        return bool(int(value))
                    if option == "directory":
                        if value == "<Enter directory here>":
                            print("FATAL: You haven't set up PyWebServer! Please edit pywebsrv.conf!")
                            exit(1)
                        return value
                    return value
        return None

    def autocert(self):
        """
        Generate some self-signed certificates using AutoCertGen
        """
        autocert = AutoCertGen()
        pk = autocert.generate_private_key()
        sub, iss = autocert.generate_issuer_and_subject()
        cert = autocert.build_cert(pk, iss, sub)
        autocert.write_cert(pk, cert)


class RequestParser:
    def __init__(self):
        self.allowed_methods_file = "allowedmethods.conf"
        self.file_handler = FileHandler()
        self.hosts = self.file_handler.read_config("host")
        self.all_allowed = self.file_handler.read_config("allow-all")

    def parse_request_line(self, line):
        """Parses the HTTP request line."""
        try:
            method, path, version = line.split(" ")
        except ValueError:
            return None, None, None
        if path.endswith("/"):
            path += "index.html"
        return method, path, version

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
        # if os.path.isfile(self.allowed_methods_file):
        #     with open(self.allowed_methods_file, "r") as f:
        #         allowed_methods = [line.strip() for line in f]
        return method in allowed_methods

    def host_parser(self, host):
        """
        Parses the host and makes sure it's allowed in
        Mfw im in an ugly code writing contest and my opponent is nova while writing a side project
        """
        host = str(host)
        if ":" in host:
            host = host.split(":", 1)[0]
        host = host.lstrip()
        if (
            host == "localhost" or host == "127.0.0.1"
        ) and self.file_handler.read_config("allow-localhost"):
            return True
        if host not in self.hosts and self.all_allowed is False:
            return False
        elif host not in self.hosts and self.all_allowed is True:
            return True


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

        # TODO: change this to something like oh no you fucked up, go fix idiot
        self.no_host_req_response = (
            "Connecting via this host is disallowed\r\n"
            "You may also be using a very old browser!\r\n"
            "Ask the owner of this website to set allow-all to 1!"
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
            "<body><center><h1>HTTP 404 - Not Found!</h1><p>Running PyWebServer/1.1</p>"
            "</center></body></html>"
        )
        self.http_403_html = (
            "<html><head><title>HTTP 403 - PyWebServer</title></head>"
            "<body><center><h1>HTTP 403 - Forbidden</h1><p>Running PyWebServer/1.1</p>"
            "</center></body></html>"
        )
        self.http_405_html = (
            "<html><head><title>HTTP 405 - PyWebServer</title></head>"
            "<body><center><h1>HTTP 405 - Method not allowed</h1><p>Running PyWebServer/1.1</p>"
            "</center></body></html>"
        )

        self.running = True

    def start(self, http, https):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

        http_thread = threading.Thread(target=self.start_http, daemon=True)
        https_thread = threading.Thread(target=self.start_https, daemon=True)

        if https is True:
            https_thread.start()
        if http is True:
            http_thread.start()

        print(
            f"Server running:\n - HTTP on port {self.http_port}\n - HTTPS on port {self.https_port}"
        )

        http_thread.join()
        https_thread.join()

    def start_http(self):
        self.http_socket.listen(5)
        print(f"HTTP server listening on port {self.http_port}...")
        while self.running:
            try:
                conn, addr = self.http_socket.accept()
                print(f"HTTP connection received from {addr}")
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
                print(f"HTTPS connection received from {addr}")
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
            response = self.handle_request(request, addr)

            if isinstance(response, str):
                response = response.encode()  # if we send text this shouldn't explode

            conn.sendall(response)
        except Exception as e:
            print(f"Error handling connection: {e}")
        finally:
            conn.close()

    def handle_request(self, data, addr):
        if not data:
            return self.build_response(400, "Bad Request")  # user did fucky-wucky

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
            if (
                self.file_handler.read_config("allow-nohost") is True
            ):  # no host is stupid
                pass
            return self.build_response(
                403, self.no_host_req_response.encode()
            )  # the default (i hope to god)

        method, path, version = self.parser.parse_request_line(request_line)

        if not all([method, path, version]) or not self.parser.is_method_allowed(
            method
        ):
            return self.build_response(405, self.http_405_html)

        file_content = self.file_handler.read_file(path)

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
            )  # The user did no fucky-wucky, but the server fucking exploded.

        # (try to) detect binary files (eg, mp3) and serve them correctly
        if path.endswith((".mp3", ".png", ".jpg", ".jpeg", ".gif")):
            return self.build_binary_response(200, file_content, path)

        return self.build_response(200, file_content)

    @staticmethod
    def build_binary_response(status_code, binary_data, filename):
        """Handles binary files like MP3s."""
        messages = {
            200: "OK",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }
        status_message = messages.get(status_code)

        # In the spirit of keeping stuff small, we'll just guess and see.
        content_type = "application/octet-stream"
        if filename.endswith(".mp3"):
            content_type = "audio/mpeg"
        elif filename.endswith(".png"):
            content_type = "image/png"
        elif filename.endswith(".jpg") or filename.endswith(".jpeg"):
            content_type = "image/jpeg"
        elif filename.endswith(".gif"):
            content_type = "image/gif"

        headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Server: PyWebServer/1.1\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(binary_data)}\r\n"
            f"Connection: close\r\n\r\n"  # connection close bcuz im lazy
        )
        return headers.encode() + binary_data

    @staticmethod
    def build_response(status_code, body):
        messages = {
            200: "OK",
            304: "Not Modified",  # TODO KEKL
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }
        status_message = messages.get(status_code)

        if isinstance(body, str):
            body = body.encode()

        headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Server: PyWebServer/1.1\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        return headers + body

    def shutdown(self, signum, frame):
        print(f"\nRecieved signal {signum}")
        print("\nShutting down server...")
        self.running = False
        self.http_socket.close()
        self.https_socket.close()
        sys.exit(0)


def main():
    file_handler = FileHandler()
    file_handler.check_first_run()
    http_port = file_handler.read_config("port") or 8080
    https_port = file_handler.read_config("port-https") or 8443
    http_enabled = file_handler.read_config("http") or True
    https_enabled = file_handler.read_config("https") or False
    server = WebServer(http_port=http_port, https_port=https_port)
    server.start(http_enabled, https_enabled)


if __name__ == "__main__":
    main()
