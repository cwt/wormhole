Wormhole
========
*(forked from https://github.com/devunt/warp)*

Simple http proxy made in python 3.5


Dependency
----------

* python >= 3.5.0


How to install
--------------

You can install **wormhole** using ``pip``:

.. code-block:: console

   $ pip install hg+https://bitbucket.org/bashell-com/wormhole

Or install from your local clone:

.. code-block:: console

   $ hg clone https://bitbucket.org/bashell-com/wormhole
   $ cd warp/
   $ pip install -e .


How to use
----------

1. run ``wormhole`` command (or you might need to run ``wormhole.py`` instead
   if setuptools isn't installed in your system)

   .. code-block:: console

      $ wormhole

2. set browser's proxy setting to 

   http proxy
      host: 127.0.0.1
      port: 8800


Command help
------------

.. code-block:: console

   $ python wormhole.py --help


License
-------

MIT License (included in ``wormhole.py``)


Notice
------

1. may not work in

   * some ISPs
   * some company firewalls
   * some school firewalls
   * some browers (will be fixed later)