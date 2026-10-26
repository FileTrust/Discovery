# Third-party notices

## Application update checks

The Update Framework (`tuf` 7.0.1), Copyright the TUF contributors, is
available under Apache-2.0 OR MIT. FileTrust uses the MIT option.
https://github.com/theupdateframework/python-tuf

`securesystemslib`, Copyright the Secure Systems Lab contributors, is MIT.
https://github.com/secure-systems-lab/securesystemslib

Full license texts are in `licenses/tuf-MIT.txt`,
`licenses/tuf-APACHE-2.0.txt` and `licenses/securesystemslib-MIT.txt`.
These dependencies are installed separately through pip; their own notices
and dependency licenses remain in the installed distributions.

## Container environment

Docker builds install Debian packages separately. Their copyright and complete
license notices remain in `/usr/share/doc/<package>/copyright` in the image.
The Python environment also retains each installed distribution's notices.
