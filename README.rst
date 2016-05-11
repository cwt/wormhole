Wormhole
========

Asynchronous I/O HTTP and HTTPS Proxy on Python 3.5

**Wormhole** is a forward proxy without caching. You may use it to:

-  Modifying requests to look like they are originated from the IP address
   that *Wormhole* is running on.
-  Adding an authentication layer to the internet users in your organization.
-  Logging internet activities to your syslog server.

Dependency
----------

-  Python >= 3.5.0
-  `uvloop <https://github.com/MagicStack/uvloop>`_ (optional)

Docker Image Usage
------------------

Run without authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ docker pull bashell/wormhole
    $ docker run -d -p 8800:8800 bashell/wormhole

Run with authentication
~~~~~~~~~~~~~~~~~~~~~~~

-  Create an empty directory on your docker host
-  Create an authentication file that contains username and password in this
   format ``username:password``
-  Link that directory to the container via option ``-v`` and also run wormhole
   container with option ``-a /path/to/authentication_file``

::

    $ docker pull bashell/wormhole
    $ mkdir -p /path/to/dir
    $ echo "user1:password1" > /path/to/dir/wormhole.passwd
    $ docker run -d -v /path/to/dir:/opt/wormhole \
      -p 8800:8800 bashell/wormhole \
      -a /opt/wormhole/wormhole.passwd

How to install
--------------

Stable Version
~~~~~~~~~~~~~~

Please install the **stable version** using ``pip`` command:

::

    $ pip install wormhole-proxy

Development Snapshot
~~~~~~~~~~~~~~~~~~~~

You can install the **development snapshot** using ``pip`` with ``mercurial``:

::

    $ pip install hg+https://bitbucket.org/bashell-com/wormhole

Or install from your local clone:

::

    $ hg clone https://bitbucket.org/bashell-com/wormhole
    $ cd wormhole/
    $ pip install -e .

You can also install the latest ``default`` snapshot using the following
command:

::

    $ pip install https://bitbucket.org/bashell-com/wormhole/get/default.tar.gz

How to use
----------

#. Run **wormhole** command

   ::

       $ wormhole

#. Set browser's proxy setting to

   ::

       host: 127.0.0.1
       port: 8800

Command help
------------

::

    $ wormhole --help

License
-------

MIT License (included in `license.py <https://goo.gl/2J8rcu>`_)

Notice
------

-  This project is forked and converted to Mercurial from
   `WARP <https://github.com/devunt/warp>`_ on GitHub.
-  Authentication file contains ``username`` and ``password`` in **plain
   text**, keep it secret! *(I will try to encrypt/encode it soon.)*
-  Wormhole may not work in:

   -  some ISPs
   -  some firewalls
   -  some browers
   -  some web sites
