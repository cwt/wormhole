WARP
====
*(forked from https://github.com/devunt/warp)*

Simple http proxy made in python 3.5

This is proof-of-concept code.

The main purpose of WARP is bypassing http://warning.or.kr/, which is a Deep Packet Inspection that operated by Korea Government.

For more information, please see https://en.wikipedia.org/wiki/Internet_censorship_in_South_Korea

You should run this proxy in your local computer.


Dependency
----------

* python >= 3.5.0

How to install
--------------

You can install **warp** using ``pip``:

.. code-block:: console

   $ pip install hg+https://bitbucket.org/bashell-com/warp

Or if you're interested in bleeding edge of the master branch give it a try:

.. code-block:: console

   $ hg clone https://bitbucket.org/bashell-com/warp
   $ cd warp/
   $ pip install -e .


How to use
----------

1. run ``warp`` command (or you might need to run ``warp.py`` instead
   if setuptools isn't installed in your system)

   .. code-block:: console

      $ warp

2. set browser's proxy setting to 

   http proxy
      host: 127.0.0.1
      port: 8800

Command help
------------

.. code-block:: console

   $ python warp.py --help

License
-------

MIT License (included in ``warp.py``)

면책조항
--------

1. WARP를 사용함으로써 생기는 모든 책임은 사용자에게 있습니다.
2. WARP의 코드 기여자들은 사용에 관한 책임을 지지 않습니다.

Notice
------

1. may not work in

   * some ISPs
   * some company firewalls
   * some school firewalls
   * some browers (will be fixed later)

Special thanks to
-----------------

* **Junehyeon Bae (https://github.com/devunt) owner of the original project.**
* peecky (https://github.com/peecky) for lots of improvement code contributes.
* Young-Ho Cha (https://github.com/ycha) for randomize feed hostname code.
* Hong Minhee (https://github.com/dahlia) for python syntax and optparse implementaion.
* Park Jeongmin (https://github.com/pjm0616) for dummy header ideas.
* EJ Lee (https://github.com/hdformat) for firefox support code.
* Inseok Lee (https://github.com/dlunch) for english grammers :p