from distutils.core import setup

setup(name='pckr',
    version='0.3',
    description='Pickr',
    author='Jon Hill',
    author_email='jon@jonhill.ca',
    url='',
    packages = ['pckr'],
    license='MIT',

    install_requires=[
        'boto',
        'flask',
        'pycryptodome',
        'blowfish',
        'requests',
        'termcolor'
    ],

    entry_points={
        'console_scripts': [
            'pckr = pckr:main'
        ]
    }
)
