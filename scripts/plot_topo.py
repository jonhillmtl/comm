import matplotlib.pyplot as plt
import networkx as nx
import sys
import os
import json

sys.path.append("..")
from pckr_client.user import User

def main():
    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)

    G = nx.Graph()
    
    for u in sorted(users):
        user = User(u)
        print("-" * 100)
        print("user {}".format(user.username))

        ipcache = json.loads(open(os.path.join(user.ipcache_path, 'cache.json')).read())
        for k in sorted(ipcache.keys()):
            v = ipcache[k]
            G.add_edge(user.username, k)
            public_key_text = user.get_contact_public_key(k)
            has_pk = public_key_text != None

    # write in UTF-8 encoding
    fh = open('edgelist.utf-8', 'wb')
    fh.write('# -*- coding: utf-8 -*-\n'.encode('utf-8'))  # encoding hint for emacs
    nx.write_multiline_adjlist(G, fh, delimiter='\t', encoding='utf-8')

    # read and store in UTF-8
    fh = open('edgelist.utf-8', 'rb')
    H = nx.read_multiline_adjlist(fh, delimiter='\t', encoding='utf-8')

    for n in G.nodes():
        if n not in H:
            print(False)

    print(list(G.nodes()))

    pos = nx.spring_layout(G)
    nx.draw(G, pos, font_size=16, with_labels=False)
    for p in pos:  # raise text positions
        pos[p][1] += 0.07
    nx.draw_networkx_labels(G, pos)
    plt.show()

main()