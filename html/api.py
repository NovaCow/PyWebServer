"""
This is the Amethyst API mode Python interface whatevers.
Docs will follow.
"""

# Below go imports.
import sys
import os

if not os.getcwd() in sys.path:
    sys.path.append(os.getcwd())
import pywebsrv


class API:
    """
    class
    """

    def __init__(self):
        # DO NOT USE THIS CLASS FOR PROGRAM, ONLY ON_REQUEST PLEASE!!
        # Below go definitions to get things working.
        self.build_response = pywebsrv.WebServer.build_binary_response

    def on_request(self, req):
        return self.build_response(200, "This is a test", "text/html")
