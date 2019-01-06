"""

use this script to generate a chart of the local network connections.

this is for testing purposes only.

usage: pckr_plot_nt

"""

import os
import json

import matplotlib.pyplot as plt
import networkx as nx

from .user import User


def main():
    """ the main handler function for this script. """

    users = []
    root = os.path.expanduser("~/pckr/")
    for sd in os.listdir(root):
        path = os.path.join(root, sd)
        if os.path.isdir(path):
            users.append(sd)

    graph = nx.DiGraph()

    for u in sorted(users):
        user = User(u)
        print("-" * 100)
        print("user {}".format(user.username))

        path = os.path.join(user.ipcache_path, 'cache.json')
        if os.path.exists(path):
            ipcache = json.loads(open(path).read())
            for k in sorted(ipcache.keys()):
                graph.add_edge(user.username, k)

    # write in UTF-8 encoding
    file_handle = open('./test/edgelist.utf-8', 'wb')
    file_handle.write('# -*- coding: utf-8 -*-\n'.encode('utf-8'))  # encoding hint for emacs
    nx.write_multiline_adjlist(graph, file_handle, delimiter='\t', encoding='utf-8')

    # read and store in UTF-8
    file_handle = open('./test/edgelist.utf-8', 'rb')
    H = nx.read_multiline_adjlist(file_handle, delimiter='\t', encoding='utf-8')

    for node in graph.nodes():
        if node not in H:
            print(False)

    print(list(graph.nodes()))

    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, font_size=16, with_labels=False)
    for p in pos:  # raise text positions
        pos[p][1] += 0.07
    nx.draw_networkx_labels(graph, pos)
    plt.show()
