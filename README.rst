Wormhole
========

**Wormhole** is a forward proxy without caching. You may use it for:

-  Modifying requests to look like they are originated from the IP address
   that *Wormhole* is running on.
-  Adding an authentication layer to the internet users in your organization.
-  Logging internet activities to your syslog server.

Dependency
----------

-  Python >= 3.6
-  `uvloop <https://github.com/MagicStack/uvloop>`_ (optional)

Docker Image Usage
------------------

Run without authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: shell

    $ docker pull bashell/wormhole
    $ docker run -d -p 8800:8800 bashell/wormhole

Run with authentication
~~~~~~~~~~~~~~~~~~~~~~~

-  Create an empty directory on your docker host
-  Create an authentication file that contains username and password in this
   format ``username:password``
-  Link that directory to the container via option ``-v`` and also run wormhole
   container with option ``-a /path/to/authentication_file``

Example:

.. code:: shell

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

.. code:: shell

    $ pip install wormhole-proxy

Development Snapshot
~~~~~~~~~~~~~~~~~~~~

You can install the **development snapshot** using ``pip`` with ``mercurial``:

.. code:: shell

    $ pip install hg+https://hg.sr.ht/~cwt/wormhole

Or install from your local clone:

.. code:: shell

    $ hg clone https://hg.sr.ht/~cwt/wormhole
    $ cd wormhole/
    $ pip install -e .

You can also install the latest ``tip`` snapshot using the following
command:

.. code:: shell

    $ pip install https://hg.sr.ht/~cwt/wormhole/archive/tip.tar.gz

How to use
----------

#. Run **wormhole** command

   .. code:: shell

       $ wormhole

#. Set browser's proxy setting to

   .. code:: shell

       host: 127.0.0.1
       port: 8800

Command help
------------

.. code:: shell

    $ wormhole --help

License
-------

MIT License (included in `license.py <https://bit.ly/wormhole-proxy-license>`_)

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
