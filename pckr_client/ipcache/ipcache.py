import os
import json

class IPCache(object):
    user = None
    data = None

    def __init__(self, user):
        self.user = user
        path = os.path.join(self.user.ipcache_path, "cache.json")
        data = dict()
        if os.path.exists(path):
            try:
                data = json.loads(open(path).read())
            except json.decoder.JSONDecodeError:
                pass
        self.data = data

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return json.dumps(self.data)

    def set_ip_port(self, username, ip, port):
        self.data[username] = dict(
            ip=ip,
            port=port
        )

        path = os.path.join(self.user.ipcache_path, "cache.json")
        with open(path, "w+") as f:
            f.write(json.dumps(self.data))

    def remove_ip_port(self, username):
        try:
            del self.data[username]
        except IndexError:
            pass

        path = os.path.join(self.user.ipcache_path, "cache.json")        
        with open(path, "w+") as f:
            f.write(json.dumps(self.data))

    def get_ip_port(self, username):
        return (self.data[username]['ip'], self.data[username]['port'])
