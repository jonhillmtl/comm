import subprocess
import random

def rpk(u1, u2, robustness=5):
    if random.randint(0, 10) < robustness:
        subprocess.check_call([
            'pckr_client',
            'rpk',
            '--username={}'.format(u1),
            '--u2={}'.format(u2)
        ])
    
        subprocess.check_call([
            'pckr_client',
            'ppk_req',
            '--username={}'.format(u2)
        ])

        subprocess.check_call([
            'pckr_client',
            'ppk_resp',
            '--username={}'.format(u1)
        ])


def aip(data, u1, u2, robustness=5):
    try:
        if random.randint(0, 10) < robustness:
            subprocess.check_call([
                'pckr_client',
                'aip',
                '--username={}'.format(u1),
                '--u2={}'.format(u2),
                '--ip={}'.format(data[u2]['ip']),
                '--port={}'.format(data[u2]['port'])
            ])
    except KeyError:
        pass
