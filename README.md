Wormhole
========

*(Forked and converted to Mercurial from [https://github.com/devunt/warp](
https://github.com/devunt/warp))*

Asynchronous IO HTTP and HTTPS Proxy on Python 3.5

Dependency
----------

*  Python >= 3.5.0


Docker Image Usage
------------------

Run without authentication

```bash
$ docker pull bashell/wormhole
$ docker run -d -p 8800:8800 bashell/wormhole
```

Run with authentication

-   Create an empty directory on your docker host
-   Create an authentication file that contains username and password in
    this format `username:password`
-   Link that directory to the container via option `-v` and also run
    wormhole container with option `-a /path/to/authentication_file`

```bash
$ docker pull bashell/wormhole
$ mkdir -p /path/to/dir
$ echo "user1:password1" > /path/to/dir/wormhole.passwd
$ docker run -d -v /path/to/dir:/opt/wormhole \
  -p 8800:8800 bashell/wormhole \
  -a /opt/wormhole/wormhole.passwd
```


How to install
--------------

You can install **wormhole** using `pip` with `mercurial`:

```bash
$ pip install hg+https://bitbucket.org/bashell-com/wormhole
```

Or install from your local clone:

```bash
$ hg clone https://bitbucket.org/bashell-com/wormhole
$ cd wormhole/
$ pip install -e .
```

You can also install the latest `default` snapshot using the following command:

```bash
$ pip install https://bitbucket.org/bashell-com/wormhole/get/default.tar.gz
```

How to use
----------

1.  Run **wormhole** command
    
    ```
    $ wormhole
    ```

2.  Set browser's proxy setting to

    ```
    host: 127.0.0.1
    port: 8800
    ```


Command help
------------

```bash
$ wormhole --help
```


License
-------

MIT License (included in [license.py](https://goo.gl/2J8rcu))


Notice
------

*  Authentication file contains `username` and `password` in **plain text**,
   keep it secret! _(I will try to encrypt/encode it soon.)_

*  Wormhole may not work in:
    -   some ISPs
    -   some firewalls
    -   some browers
