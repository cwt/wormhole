try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from wormhole.version import VERSION


def readme():
    with open("README.md", encoding="utf-8") as readme_file:
        return "\n" + readme_file.read()


setup(
    name="wormhole-proxy",
    version=VERSION.replace("v", ""),  # normalize version from vd.d to d.d
    author="Chaiwat Suttipongsakul",
    author_email="cwt@bashell.com",
    url="https://hg.sr.ht/~cwt/wormhole",
    license="MIT",
    description="Asynchronous I/O HTTP and HTTPS Proxy on Python >= 3.11",
    long_description=readme(),
    long_description_content_type="text/markdown",
    keywords="wormhole asynchronous web proxy",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Internet :: Proxy Servers",
    ],
    setup_requires=["setuptools>=40.1.0"],
    install_requires=[
        'pywin32;platform_system=="Windows"',
    ],
    extras_require={
        "performance": [
            'winloop;platform_system=="Windows"',
            'uvloop;platform_system!="Windows"',
        ],
    },
    packages=["wormhole"],
    include_package_data=True,
    entry_points={"console_scripts": ["wormhole = wormhole.proxy:main"]},
)
