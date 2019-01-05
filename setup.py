""" the setup file for pckr. """

from distutils.core import setup

setup(
    name='pckr',
    version='0.3',
    description='Pickr',
    author='Jon Hill',
    author_email='jon@jonhill.ca',
    url='',
    packages=['pckr'],
    license='MIT',

    install_requires=[
        'blowfish',
        'boto',
        'flask',
        'pycryptodome',
        'requests',
        'termcolor'
    ],

    entry_points={
        'console_scripts': [
            'pckr = pckr.client:main',
            'pckr_nt = pckr.nt:main',
            'pckr_plot_nt = pckr.plot_nt:main'
        ]
    }
)
