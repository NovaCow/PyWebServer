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

TODO: INPROG: add typing to all code, new code will feature it by default.
"""

import os
import mimetypes
import threading
import ssl
import socket

# import re
import signal
import sys

try:
    if not os.getcwd() in sys.path:
        sys.path.append(f"{os.getcwd()}")
    from .certgen import AutoCertGen
except ImportError:
    # just do nothing, it's not working anyway.
    print(
        "WARN: You need the AutoCertGen plugin! Please install it from\n"
        "https://git.novacow.ch/Nova/AutoCertGen/"
    )
    # pass

AMETHYST_BUILD_NUMBER = "b0.2.0-0072"
AMETHYST_REPO = "https://git.novacow.ch/Nova/PyWebServer/"


class ConfigParser:
    def __init__(self, text):
        self.data: dict = {"hosts": {}, "globals": {}}
        self._parse(text)

    def _parse(self, text):
        lines: list = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        current_block: tuple | None = None
        current_name: str | None = None

        for line in lines:
            if line.startswith("host ") and line.endswith("{"):
                current_name = line.split()[1]
                self.data["hosts"][current_name] = {}
                current_block = ("host", current_name)
                continue

            if line == "globals {":
                current_block = ("globals", None)
                continue

            if line == "}":
                current_block = None
                current_name = None
                continue

            if ":" in line and current_block:
                key, value = line.split(":", 1)
                key: str = key.strip()
                value: str = value.strip()

                if "," in value:
                    value = [v.strip() for v in value.split(",")]

                if current_block[0] == "host":
                    self.data["hosts"][current_name][key] = value
                else:
                    self.data["globals"][key] = value

    def query_config(self, key, host=None):
        if host:
            return self.data["hosts"].get(host, {}).get(key)
        if key == "hosts":
            print(f"\n\n\nHosts!\nHosts: {self.data['hosts']}\n\n\n")
            return list(self.data["hosts"].keys())
        return self.data["globals"].get(key)


class FileHandler:
    def __init__(self, base_dir=None):
        # this is a fucking clusterfuck.
        self.config_file = "amethyst.conf"
        self.config_path = os.path.join(os.getcwd(), self.config_file)
        with open(self.config_path, "r") as f:
            self.cfg = ConfigParser(f.read())
        self.base_dir = self.read_config("directory")
        if not os.path.exists(self.config_path):
            # uuh???
            print(
                "The amethyst.conf file needs to be in the same directory "
                "as amethyst.py! Get the default config file from:\n"
                "https://git.novacow.ch/Nova/PyWebServer/raw/branch/2.0/amethyst.conf"
            )
            exit(1)
        # TODO: fix this please!!

    def read_file(self, file_path, directory=None):
        if "../" in file_path or "%" in file_path:
            return 403, None
        if file_path == "api.py":
            return 404, None

        if directory is not None:
            full_path = os.path.join(directory, file_path.lstrip("/"))
        else:
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

    def write_file(self, file_path, data, directory=None):
        if "../" in file_path or "%" in file_path:
            return 403
        full_path = os.path.join(self.base_dir, file_path.lstrip("/"))
        with open(full_path, "a") as f:
            f.write(data)
        return 0

    def read_config(self, key, host_name=None):
        print(
            f"\n\n\nQuery!\nkey: {key}\nhost_name: {host_name}\nret: {self.cfg.query_config(key, host_name)}"
        )
        return self.cfg.query_config(key, host_name)

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
        self.hosts = self.file_handler.read_config("hosts")
        print(f"Hosts: {self.hosts}")

    def parse_request_line(self, line, host):
        """Parses the HTTP request line."""
        try:
            method, path, version = line.split(" ")
        except ValueError:
            return None, None, None
        if path.endswith("/") or ("." not in path):
            if not path.endswith("/"):
                path += "/"
            index = self.file_handler.read_config("index", host) or "index.html"
            path += f"{index}"
        return method, path, version

    def parse_match_blocks(self, to_parse: str | list):
        if isinstance(to_parse, str):
            to_parse = [to_parse]
        match = []
        literal = []
        for block in to_parse:
            if block.startswith('match("'):
                adx = block[7:-2]
                match.append(adx)
            else:
                literal.append(block)
        return match, literal

    def ua_is_allowed(self, ua, host=None):
        """Parses and matches UA to block"""
        # return True
        _list = self.file_handler.read_config("block-ua", host)
        if _list is None:
            return True
        match, literal = self.parse_match_blocks(_list)
        if ua in literal:
            return False
        for _ua in match:
            if _ua.lower() in ua.lower():
                return False
        return True

    def is_method_allowed(self, method, host=None):
        """
        Checks if the HTTP method is allowed.
        Reads allowed methods from a configuration file.
        Falls back to allowing only 'GET' if the file does not exist.
        Should (for now) only be GET as I haven't implemented the logic for PUT
        """
        allowed_methods = self.file_handler.read_config("allowed-methods", host)
        if allowed_methods is None:
            allowed_methods = ["GET"]
        return method in allowed_methods

    def host_parser(self, host):
        """
        Parses the host and makes sure it's allowed in
        Mfw im in an ugly code writing contest and my opponent is nova while writing a side project
        """
        host = f"{host}"
        print(f"hosts: {self.hosts}, host: {host}, split: {host.rsplit(':', 1)[0]}")
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        host = host.lstrip()
        host = host.rstrip()
        if self.hosts is None:
            return True
        if host not in self.hosts:
            if "*" in self.hosts:
                return "catchall"
            return False
        else:
            return True


class ProxyServer:
    def __init__(self, fh):
        self.file_handler: FileHandler = fh

    def try_connection(
        self, host: str, port: int, data: bytes, chost: str, force_tls: bool = None
    ):
        if port in [443, 8443, 9443]:
            do_tls = True
        else:
            if force_tls is True:
                do_tls = True
            else:
                do_tls = False
        print(f"\n\n\nchost: {chost}\n\n\n")
        nhost = self.file_handler.read_config("proxy", chost)
        print(f"\n\n\nnhost: {nhost}\n\n\n")
        if ":" in nhost:
            nport = int(nhost.split(":")[1])
            nhost = nhost.split(":")[0]
        else:
            nport = port
        print(f"{nhost}, {nport}, {data}")
        data = self.reset_host(nhost, nport, data)
        try:
            return self.tcp_send(host, port, data, do_tls)
        except Exception:
            if do_tls is False:
                print("Retrying with TLS...")
                return self.try_connection(host, port, data, chost, True)
            else:
                raise

    @staticmethod
    def reset_host(host: str, port: int, data: bytes):
        data = data.decode()
        data = data.splitlines()
        for line in data:
            print(line)
            if line.startswith("Host:"):
                if port not in [80, 443]:
                    new_line = f"Host: {host}:{port}"
                else:
                    new_line = f"Host: {host}"
                idx = data.index(line)
                data[idx] = new_line
                print(f"\n\n\n{idx}\n\n\n")
            if line.startswith("Connection:"):
                idx = data.index(line)
                new_line = "Connection: close"
                data[idx] = new_line
        data = "\r\n".join(data)
        data = f"{data}\r\n\r\n"
        print(data)
        return data.encode()
        # return data

    @staticmethod
    def create_tls_context():
        # Create a context that by default verifies with system CAs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def tcp_send(self, host, port, data: bytes, do_tls: bool):
        try:
            with socket.create_connection((host, port), timeout=10) as raw_sock:
                raw_sock.settimeout(10)
                if do_tls:
                    ctx = self.create_tls_context()
                    server_hostname = host
                    with ctx.wrap_socket(
                        raw_sock, server_hostname=server_hostname
                    ) as ssock:
                        ssock.sendall(data)
                        print("data reached")
                        return ssock.recv(512000)
                else:
                    raw_sock.sendall(data)
                    return raw_sock.recv(512000)
        except Exception:
            raise


class WebServer:
    def __init__(
        self, http_port=8080, https_port=8443, cert_file="cert.pem", key_file="key.pem"
    ):
        self.http_port = int(http_port)
        self.https_port = int(https_port)
        self.file_handler = FileHandler()
        self.parser = RequestParser()
        self.cert_file = self.file_handler.read_config("cert") or cert_file
        self.key_file = self.file_handler.read_config("key") or key_file
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

        self.http_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.http_socket.bind(("::", self.http_port))

        self.https_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.https_socket.bind(("::", self.https_port))

        self.proxy_handler = ProxyServer(self.file_handler)

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
            "<html><head><title>HTTP 404 - Amethyst</title></head>"
            f"<body><center><h1>HTTP 404 - Not Found!</h1><p>Running Amethyst/build-{AMETHYST_BUILD_NUMBER}</p>"
            "</center></body></html>"
        )
        self.http_403_html = (
            "<html><head><title>HTTP 403 - Amethyst</title></head>"
            f"<body><center><h1>HTTP 403 - Forbidden</h1><p>Running Amethyst/build-{AMETHYST_BUILD_NUMBER}</p>"
            "</center></body></html>"
        )
        self.http_405_html = (
            "<html><head><title>HTTP 405 - Amethyst</title></head>"
            f"<body><center><h1>HTTP 405 - Method not allowed</h1><p>Running Amethyst/build-{AMETHYST_BUILD_NUMBER}</p>"
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
                if yn.lower() == "n":
                    exit(1)
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
            data = conn.recv(32768)
            request = data.decode(errors="ignore")
            if not data:
                response = self.build_response(
                    400, "Bad Request"
                )  # user did fucky-wucky
            elif len(data) > 8192:
                response = self.build_response(413, "Request too long")
            else:
                response = self.handle_request(request, addr)

            if isinstance(response, str):
                response = response.encode()

            print(len(response))
            conn.sendall(response)
        except Exception as e:
            print(f"Error handling connection: {e}")
            response = self.build_response(
                500,
                "Amethyst is currently unable to serve your request. Below is debug info.\r\n"
                f"Error: {e}; Version: amethyst-b{AMETHYST_BUILD_NUMBER}\r\n"
                "You cannot do anything at this time, the server owner has made a misconfiguration or there is a bug in the program",
            )
            conn.sendall(response)
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
                if allowed == "catchall":
                    host = "*"
                    allowed = True
                if not allowed:
                    return self.build_response(
                        403, "Connecting via this host is disallowed."
                    )
                break
        else:
            return self.build_response(400, self.no_host_req_response.encode())

        for line in data.splitlines():
            if "User-Agent" in line:
                ua = line.split(":", 1)[1].strip()
                allowed = self.parser.ua_is_allowed(ua, host)
                if not allowed:
                    return self.build_response(
                        403, "This UA has been blocked by the owner of this site."
                    )
                break
        else:
            return self.build_response(400, "You cannot connect without a User-Agent.")

        if ":" in host:
            host = host.rsplit(":", 1)[0]
        else:
            host = host

        method, path, version = self.parser.parse_request_line(request_line, host)

        if not all([method, path, version]):
            return self.build_response(400, "Bad Request")

        if self.file_handler.read_config("proxy", host) is not None:
            orig_host = host
            value = self.file_handler.read_config("proxy", host)
            if ":" in value:
                host = value.split(":")[0]
                port = int(value.split(":")[1])
            else:
                host = value
                port = 443
            return self.proxy_handler.try_connection(
                host,
                port,
                data.encode(),
                orig_host,
            )

        # Figure out a better way to reload config
        if path == "/?pywebsrv_reload_conf=1":
            print("Got reload command! Reloading configuration...")
            self.file_handler = FileHandler()
            self.parser = RequestParser()
            return self.build_response(302, "", host=host)

        if not self.parser.is_method_allowed(method):
            return self.build_response(405, self.http_405_html)

        directory = (
            self.file_handler.read_config("directory", host)
            or self.file_handler.base_dir
        )

        if self.file_handler.read_config("apimode", host) is True:
            if not os.path.join(os.getcwd(), directory) in sys.path:
                sys.path.append(f"{os.path.join(os.getcwd(), directory)}")
            import api

            apiclass = api.API()
            return apiclass.on_request(data)

        file_content, mimetype = self.file_handler.read_file(path, directory)

        if file_content == 403:
            print("WARN: Directory traversal attack prevented.")  # look ma, security!!
            return self.build_response(403, self.http_403_html)
        if file_content == 404:
            return self.build_response(404, self.http_404_html)
        if file_content == 500:
            return self.build_response(
                500,
                "Amethyst has encountered a fatal error and cannot serve "
                "your request. Contact the owner with this error: FATAL_FILE_RO_ACCESS",
            )  # When there was an issue with reading we throw this.

        mimetype = mimetype[0]
        if mimetype is None:
            # We have to assume it's binary.
            return self.build_binary_response(
                200, file_content, "application/octet-stream"
            )
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
            500: "Internal Server Error",
        }
        status_message = messages.get(status_code)
        headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Server: Amethyst/amethyst-build-{AMETHYST_BUILD_NUMBER}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(binary_data)}\r\n"
            f"Connection: close\r\n\r\n"
            # Connection close is done because it is way easier to implement.
            # It's not like this program will see production use anyway.
        )
        return headers.encode() + binary_data

    @staticmethod
    def build_response(status_code, body, host=None):
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
            621: "fuck off! :3",
        }
        status_message = messages.get(status_code)

        if isinstance(body, str):
            body = body.encode()

        # TODO: dont encode yet, and i encode. awesome comments here.
        # Don't encode yet, if 302 status code we have to include location.
        headers = (
            f"HTTP/1.1 {status_code} {status_message}\r\n"
            f"Server: Amethyst/build-{AMETHYST_BUILD_NUMBER}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        if status_code == 302:
            # 302 currently only happens when the reload is triggered.
            # Why not 307, Moved Permanently? Because browsers will cache the
            # response and not send the reload command.
            # if port == 443:
            #     host = f"https://{host}/"
            # else:
            #     host = f"http://{host}/"
            headers = (
                f"HTTP/1.1 {status_code} {status_message}\r\n"
                f"Location: {host}\r\n"
                f"Server: Amethyst/build-{AMETHYST_BUILD_NUMBER}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()

        if status_code == 621:
            headers = (
                f"HTTP/1.1 {status_code} {status_message}\r\n"
                "Server: Amethyst/build-0621\r\n"
                "Content-Length: 30\r\n"
                f"Connection: close\r\n\r\n"
            )
            body = "https://e621.net/posts/6155664"

        print(f"{headers + body}")
        return headers + body

    def shutdown(self, signum, frame):
        print("\nRecieved signal to exit!\nShutting down server...")
        self.running = False
        self.http_socket.close()
        self.https_socket.close()
        sys.exit(0)


def main():
    print(
        "WARNING!!\n"
        f"This is Amethyst alpha build {AMETHYST_BUILD_NUMBER}\n"
        "Since this is an alpha version of Amethyst, most features aren't working!\n"
        "These builds are also very verbose and will spit out a lot on the terminal. "
        "As you can imagine, this is for debugging purposes.\n"
        "THERE IS ABSOLUTELY NO SUPPORT FOR THESE VERSIONS!\n"
        "DO NOT USE THEM IN PRODUCTION SETTINGS!\n"
        f"Please report any bugs on {AMETHYST_REPO}\n"
    )
    input("Press <Enter> to continue. ")
    file_handler = FileHandler()
    file_handler.base_dir = file_handler.read_config("directory")
    http_port = file_handler.read_config("port") or 8080
    https_port = file_handler.read_config("https-port") or 8443
    http_enabled = bool(file_handler.read_config("http")) or True
    print(http_enabled)
    https_enabled = bool(file_handler.read_config("https")) or False
    print(https_enabled)
    server = WebServer(http_port=http_port, https_port=https_port)
    server.start(http_enabled, https_enabled)


if __name__ == "__main__":
    main()
