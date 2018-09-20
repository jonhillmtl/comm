import os
from ..user import User


class IPCache(object):
    user = None

    def __init__(self, user):
        self.user = user

    def set_ip_port(self, username, ip, port):
        

    def get_ip_port(self, username):
        pass
