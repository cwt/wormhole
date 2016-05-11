try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from wormhole.proxy import VERSION


def readme():
    with open('README.rst', encoding = 'utf-8') as readme_file:
        return readme_file.read()


setup(
    name='wormhole-proxy',
    version=VERSION.replace('v',''),  # normalize version from vd.d to d.d
    description='Asynchronous IO HTTP and HTTPS Proxy on Python 3.5',
    long_description=readme(),
    url='https://bitbucket.org/bashell-com/wormhole',
    author='Chaiwat Suttipongsakul',
    author_email='cwt@bashell.com',
    license='MIT License',
    packages=['wormhole'],
    include_package_data=True,
    entry_points={'console_scripts': ['wormhole = wormhole.proxy:main']},
    platforms='POSIX',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
