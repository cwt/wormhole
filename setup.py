try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def readme():
    with open('README.rst', encoding = 'utf-8') as f:
        return f.read()


setup(
    name='warp-proxy',
    version='0.2.0-py35',
    description='Simple http transparent proxy made in Python 3.5',
    long_description=readme(),
    url='https://github.com/bashell-com/warp',
    author='Chaiwat Suttipongsakul',
    author_email='cwt' '@' 'bashell.com',
    license='MIT License',
    py_modules=['warp'],
    entry_points='''
        [console_scripts]
        warp = warp:main
    ''',  # for setuptools
    scripts=['warp.py'],  # for distutils without setuptools
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: WWW/HTTP',
    ]
)
