import os
import json
import subprocess

def main():
    path = os.path.expanduser("~/pckr/surfaced.json")
    data = json.loads(open(path).read())

    subprocess.check_call([
        'pckr_client',
        'aip',
        '--username=123',
        '--u2=234',
        '--ip={}'.format(data['234']['ip']),
        '--port={}'.format(data['234']['port'])
    ])

    subprocess.check_call([
        'pckr_client',
        'aip',
        '--username=234',
        '--u2=345',
        '--ip={}'.format(data['345']['ip']),
        '--port={}'.format(data['345']['port'])
    ])
    
    subprocess.check_call([
        'pckr_client',
        'aip',
        '--username=234',
        '--u2=123',
        '--ip={}'.format(data['123']['ip']),
        '--port={}'.format(data['123']['port'])
    ])

    subprocess.check_call([
        'pckr_client',
        'aip',
        '--username=345',
        '--u2=234',
        '--ip={}'.format(data['234']['ip']),
        '--port={}'.format(data['234']['port'])
    ])

    # TODO JHILL: surface users here...
    subprocess.check_call([
        'pckr_client',
        'rpk',
        '--username=123',
        '--u2=234'
    ])
    
    subprocess.check_call([
        'pckr_client',
        'ppk_req',
        '--username=234'
    ])

    subprocess.check_call([
        'pckr_client',
        'ppk_resp',
        '--username=123'
    ])
    
    subprocess.check_call([
        'pckr_client',
        'rpk',
        '--username=234',
        '--u2=345'
    ])
    
    subprocess.check_call([
        'pckr_client',
        'ppk_req',
        '--username=345'
    ])

    subprocess.check_call([
        'pckr_client',
        'ppk_resp',
        '--username=234'
    ])

if __name__ == '__main__':
    main()