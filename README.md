XGeoIP is an Apache2 module that implements geo-localization, based on the remote client IP address.
It relies on MaxMind GeoIP databases for efficient IP addresses lookup (i.e. you need to download
either a free "limited", or buy a complete "accurate" version of one of their databases). Since
MaxMind already provides an Apache module, the rationale behind this development may look tweaked
somehow, but this module provides unique features that the original module from MaxMind doesn't:

* GeoIP C library independence: the XGeoIP module is completely self-contained, and does not depend
  on third-parties libraries (the databases traversal algorithm was re-implemented directly in the
  module)

* Memory model: whereas the original module databases lookup is either file- or shared-memory-based,
  the XGeoIP module uses mapped memory for efficiency in a multi-processes parent/child environment
  (like the traditional forked MPM in Apache2)

* Performance: using the memory mapped strategy, only needed databases blocks are loaded (and cached
  by the OS VM) during databases traversal; these blocks are instantaneously available to all Apache
  processes. Also, mapped memory is generally faster than shared memory on most OSes.

* Secured proxy support: when the actual web server is located behind a (reverse) proxy, the
  received IP address is the proxy's and not the originating client's. The XGeoIP module provides
  support for retrieving the originating client IP address through an HTTP header, only sent from
  authorized proxies (to avoid potential IP spoofing attacks).

* Secured information cache cookie: IP addresses lookup may be expensive on busy web servers (even
  if the MaxMind algorithm is actually very fast). The XGeoIP module provides support for a secure
  "cache" session cookie containing the geo-localization information from the first databases
  lookup: this cookie will be passed back and forth between the client browser and the server,
  speeding up geo-localization information retrieval (no databases traversal will be involved as
  long as the client session lasts and its IP address doesn't change).

