OTP Generator for Maemo
======================

Description
-----------

One-time password generator for Maemo (Fremantle and Leste). Supports OAUTH
tokens (HOTP, TOTP) as well as the Mobile-OTP algorithm.

Building
--------

If you wish to rebuild the package from source, then you will need to run the
following commands in your development environment:

    $ autoreconf --force --install
    $ ./configure
    $ make

Installation
------------

Install the 'otp' package, either through the 'App Manager' or by running (as
root):

    # apt-get install otp

See also
--------

* RFC4226 for the HOTP and TOTP standard
* [motp.sf.net](http://motp.sourceforge.net) for a description of the MOTP algorithm
