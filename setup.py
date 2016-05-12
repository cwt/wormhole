try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from wormhole.proxy import VERSION


def readme():
    with open('README.rst', encoding = 'utf-8') as readme_file:
        return '\n' + readme_file.read()


setup(
    name='wormhole-proxy',
    version=VERSION.replace('v',''),  # normalize version from vd.d to d.d
    author='Chaiwat Suttipongsakul',
    author_email='cwt@bashell.com',
    url='https://bitbucket.org/bashell-com/wormhole',
    license='MIT',
    description='Asynchronous I/O HTTP and HTTPS Proxy on Python 3.5',
    long_description=readme(),
    keywords='wormhole asynchronous web proxy',
    platforms='POSIX',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: Proxy Servers',
    ],
    packages=['wormhole'],
    include_package_data=True,
    entry_points={'console_scripts': ['wormhole = wormhole.proxy:main']},
)
