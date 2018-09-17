from distutils.core import setup

setup(name='pckr_client',
    version='0.3',
    description='Pickr',
    author='Jon Hill',
    author_email='jon@jonhill.ca',
    url='',
    packages = ['pckr_client'],
    license='MIT',

    install_requires=[
        'boto',
        'flask',
        'pycryptodome'
    ],

    entry_points={
        'console_scripts': [
            'pckr_client = pckr_client:main'
        ]
    }
)
