Compilation
===========

In order to compile and use the XGeoIP module, a decent C compiler (i.e. GCC) and an Apache2 server
and development environment must be available. This is typically achieved by installing the relevant
pre-compiled packages for the used distribution. For instance under Ubuntu Linux, you'll need the
following packages (some of them being automatically installed by others):

* gcc
* gcc-4.0
* gcc-4.0-base
* libtool
* apache2
* apache2-common
* apache2-threaded-dev (or apache2-prefork-dev)
* libapr0

Once all the above packages are installed, you should issue the following command (as a regular
non-privileged user):

    apxs2 -g -n xgeoip

This will create and populate an xgeoip folder in the current directory. Change your current
directory to this new folder and copy the mod_xgeoip.c and mod_xgeoip.h files (overwriting the
automatically generated mod_xgeoip.c), and issue the following command (still as a regular
non-privileged user):

    apxs2 -c mod_xgeoip.c

If the compilation script ran without errors, you should proceed to the next step (installation).

Installation
============

In order to install the compiled module library into the web server modules folder, you'll need root
(privileged) access to the system. Once loggued as root, issue the following command:

    apxs -c -i mod_xgeoip.c

If the installation script ran without errors, you should check that the module shared library was
correctly copied to the Apache modules folder (typically /usr/lib/apache2/modules). Once configured
and enabled (see below), you should see a line like this in the Apache web server error log, at
starting or re-starting time:

    [notice] XGeoIP Version 1.10 started (2 databases loaded)
    [notice] XGeoIP Using database /usr/share/GeoIP/GeoIPCity.dat (CITY edition - 28998859 bytes - 4143118 segments)
    [notice] XGeoIP Using database /usr/share/GeoIP/GeoIPASNum.dat (ASNUM edition - 1977281 bytes - 240051 segments)

You should of course have at least one MaxMind database available on the server (and correctly
configured as specified below) in order to start the module. When a new version of the databases is
made available by MaxMind, you should proceed as follow to upgrade:

* rename the current databases files (for instance, append a .old extension)
* copy the new databases files under the name referenced in the web server configuration file
  (dev:XGeoIPDatabases directive)
* issue an Apache graceful (a.k.a. soft) restart

A line similar to the above will be sent to the web server error log and the new databases will be
used (old databases files can be removed).

Configuration
=============

Several configuration directives can be used within the Apache web server configuration file to
tailor the module behavior to your needs. They must be inserted at the top-most level (server config
level), i.e. outside any <VirtualHost>, <Directory>, <Location> or <Files> sections and .htaccess
local files. First, you need to load the newly installed module by adding the following line to the
Apache configuration file:

    LoadModule xgeoip_module /usr/lib/apache2/modules/mod_xgeoip.so

You'll find an exhaustive list of available directives and their respective syntax below.

The `XGeoIP` directive enables (when set to on) the whole XGeoIP module (default is off).

    XGeoIP <on | off>

The `XGeoIPMode` directive indicates how geo-localization information should be passed to the other
Apache modules (default is both):

* env: through environment variables (available within PHP using the global $_SERVER array)
* notes: through Apache module notes (available within PHP using the apache_note function)
* both: through both environment variables and Apache module notes at the same time

See the examples in the *Programming* section below. Please note that the env method may not be
compatible with the Apache threaded or worker MPMs.

    XGeoIPMode [env | notes | both]

The `XGeoIPCookie` directive enables (when set to on) the generation and use of a geo-localization
information cache cookie (default is off).

    XGeoIPCookie <on | off>

The `XGeoIPCookieName` directive sets the geo-localization information cache cookie name (default is
XGEOIP).

    XGeoIPCookieName <name>

The `XGeoIPCookieDomain` directive sets the geo-localization information cache cookie domain
(default is blank, i.e. the current URI domain as determined by the browser).

    XGeoIPCookieDomain <domain>

The `XGeoIPCookieKey` directive sets the geo-localization information cache cookie security key
(default is blank, i.e. no security).

    XGeoIPCookieKey <key>

The `XGeoIPProxyHeader` directive sets the name of the HTTP header containing the originating client
IP address, when the request is being proxy-ed (default is X-Forwarded-For).

    XGeoIPProxyHeader <name>

The `XGeoIPProxyList` directive sets the proxies authorized addresses (default is blank, i.e. all
proxies are authorized). Up to 32 different space-separated addresses can be specified (the extra
values are ignored).

    XGeoIPProxyList <a.b.c.d[/prefix-length]> [... <a.b.c.d[/prefix-length]>]

The `XGeoIPDatabases` directive sets the MaxMind GeoIP databases absolutes paths (default is blank,
i.e. no database is configured and the module will not even start). Up to 8 different
space-separated databases can be specified (the extra values are ignored).

    XGeoIPDatabases <path> [<path> [...]]

In addition to the standard request processing to determine geo-localization information from the
client IP address, the XGeoIP module also implements a request handler that will output the
retrieved geo-localization information back to the client, in either plain text, XML or JSON
formats. This handler can be activated anywhere in the Apache web server configuration file, by
adding the following lines:

    <Location /path/to/the/xgeoip/handler>
      SetHandler xgeoip
    </Location>

Then, a request to http://server/path/to/the/xgeoip/handler would output something like:

    module_version 1.10
    database_date 2007-07-30
    remote_ip 81.56.47.92
    proxy_ip 0.0.0.0
    country_code2 FR
    country_code3 FRA
    country_name France
    continent_code EU
    continent_name Europe
    region_code A8
    region_name Ile-de-France
    city_name Paris
    zip_code 75013
    latitude 48.8667000000000
    longitude 2.3333000000000
    as_number AS12322
    as_name AS for Proxad/Free ISP

A "fake" virtual XML document may be added to the request to change the output format to XML, i.e. a
request to http://server/path/to/the/xgeoip/handler/fake.xml would output something like:

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <xgeoip module_version="1.10" database_date="2007-07-30">
      <remote_ip>81.56.47.92</remote_ip>
      <proxy_ip>0.0.0.0</proxy_ip>
      <country_code2>FR</country_code2>
      <country_code3>FRA</country_code3>
      <country_name>France</country_name>
      <continent_code>EU</continent_code>
      <continent_name>Europe</continent_name>
      <region_code>A8</region_code>
      <region_name>Ile-de-France</region_name>
      <city_name>Paris</city_name>
      <zip_code>75013</zip_code>
      <latitude>48.8667000000000</latitude>
      <longitude>2.3333000000000</longitude>
      <as_number>AS12322</as_number>
      <as_name>AS for Proxad/Free ISP<as_name>
    </xgeoip>

A "fake" virtual JSON document may be added to the request to change the output format to JSON, i.e.
a request to http://server/path/to/the/xgeoip/handler/fake.json would output something like:

    {
     "module_version": "1.10",
     "database_date": "2007-07-30",
     "remote_ip": "81.56.47.92",
     "proxy_ip": "0.0.0.0",
     "country_code2": "FR",
     "country_code3": "FRA",
     "country_name": "France",
     "continent_code": "EU",
     "continent_name": "Europe",
     "region_code": "A8",
     "region_name": "Ile-de-France",
     "city_name": "Paris",
     "zip_code": "75013",
     "latitude": "48.8667000000000",
     "longitude": "2.3333000000000",
     "as_number": "AS12322"
     "as_name": "AS for Proxad/Free ISP"
    }

The IP address used to gather geo-localization information is the received client IP address by
default. An additional "?remote=a.b.c.d" query parameter may also be appended to the request, in
which case the specified IP address will be used as the client IP address, paving the way to an
effective distributed geo-localization webservice mechanism.

Programming
===========

As described in the *Configuration* section, geo-localization information is passed to the other
Apache module (i.e. PHP interpreter mod_php for instance) using environment variables or/and Apache
module notes. An exhaustive list of these variables (with their meaning) is given below (unless
specified, all values default to blank if the received IP address cannot be found in the databases).

* XGEOIP_MODULE_VERSION: the version of the XGeoIP module (currently 1.10)
* XGEOIP_DATABASE_DATE: the modification date of the loaded databases files (for instance 2007-07-30)
* XGEOIP_REMOTE_IP: the remote client IP address (in a.b.c.d notation)
* XGEOIP_PROXY_IP: the proxy IP address (in a.b.c.d notation) if relevant (defaults to 0.0.0.0)
* XGEOIP_COUNTRY_CODE2: the 2-letters uppercased country ISO code (for instance FR)
* XGEOIP_COUNTRY_CODE3: the 3-letters uppercased country ISO code (for instance FRA)
* XGEOIP_COUNTRY_NAME: the human-readable English country name (for instance France)
* XGEOIP_CONTINENT_CODE: the 2-letters uppercased continent ISO code (for instance EU)
* XGEOIP_CONTINENT_NAME: the human-readable English continent name (for instance Europe)
* XGEOIP_REGION_CODE (COUNTRY edition only): the 2-letters uppercased region code (for instance A8)
* XGEOIP_REGION_NAME (COUNTRY edition only): the human-readable localized region name (for instance Ile-de-France)
* XGEOIP_CITY_NAME (COUNTRY edition only): the human-readable localized city name (for instance Paris)
* XGEOIP_ZIP_CODE (COUNTRY edition only): the country-dependent zipcode (for instance 75013)
* XGEOIP_LATITUDE (COUNTRY edition only): the geodesic latitude (defaults to 0.0000000000000)
* XGEOIP_LONGITUDE (COUNTRY edition only): the geodesic longitude (defaults to 0.0000000000000)
* XGEOIP_AS_NUMBER (ASNUM edition only): the AS number (for instance AS12322)
* XGEOIP_AS_NAME (ASNUM edition only): the AS description (for instance AS for Proxad/Free ISP)

Based on this information, the following sample PHP script:

    <pre>
    <?php
     echo "XGEOIP_MODULE_VERSION [" . @$_SERVER['XGEOIP_MODULE_VERSION'] . "]<br>" .
          "XGEOIP_DATABASE_DATE  [" . @$_SERVER['XGEOIP_DATABASE_DATE']  . "]<br>" .
          "XGEOIP_REMOTE_IP      [" . @$_SERVER['XGEOIP_REMOTE_IP']      . "]<br>" .
          "XGEOIP_PROXY_IP       [" . @$_SERVER['XGEOIP_PROXY_IP']       . "]<br>" .
          "XGEOIP_COUNTRY_CODE2  [" . @$_SERVER['XGEOIP_COUNTRY_CODE2']  . "]<br>" .
          "XGEOIP_COUNTRY_CODE3  [" . @$_SERVER['XGEOIP_COUNTRY_CODE3']  . "]<br>" .
          "XGEOIP_COUNTRY_NAME   [" . @$_SERVER['XGEOIP_COUNTRY_NAME']   . "]<br>" .
          "XGEOIP_CONTINENT_CODE [" . @$_SERVER['XGEOIP_CONTINENT_CODE'] . "]<br>" .
          "XGEOIP_CONTINENT_NAME [" . @$_SERVER['XGEOIP_CONTINENT_NAME'] . "]<br>" .
          "XGEOIP_REGION_CODE    [" . @$_SERVER['XGEOIP_REGION_CODE']    . "]<br>" .
          "XGEOIP_REGION_NAME    [" . @$_SERVER['XGEOIP_REGION_NAME']    . "]<br>" .
          "XGEOIP_CITY_NAME      [" . @$_SERVER['XGEOIP_CITY_NAME']      . "]<br>" .
          "XGEOIP_ZIP_CODE       [" . @$_SERVER['XGEOIP_ZIP_CODE']       . "]<br>" .
          "XGEOIP_LATITUDE       [" . @$_SERVER['XGEOIP_LATITUDE']       . "]<br>" .
          "XGEOIP_LONGITUDE      [" . @$_SERVER['XGEOIP_LONGITUDE']      . "]<br>" .
          "XGEOIP_AS_NUMBER      [" . @$_SERVER['XGEOIP_AS_NUMBER']      . "]<br>" .
          "XGEOIP_AS_NAME        [" . @$_SERVER['XGEOIP_AS_NAME']        . "]<br>";
    ?>
    </pre>

would produce the following output (provided that the `XGeoIPMode` directive is set to "env" or "both"):

    XGEOIP_MODULE_VERSION [1.10]
    XGEOIP_DATABASE_DATE  [2007-07-30]
    XGEOIP_REMOTE_IP      [81.56.47.92]
    XGEOIP_PROXY_IP       [0.0.0.0]
    XGEOIP_COUNTRY_CODE2  [FR]
    XGEOIP_COUNTRY_CODE3  [FRA]
    XGEOIP_COUNTRY_NAME   [France]
    XGEOIP_CONTINENT_CODE [EU]
    XGEOIP_CONTINENT_NAME [Europe]
    XGEOIP_REGION_CODE    [A8]
    XGEOIP_REGION_NAME    [Ile-de-France]
    XGEOIP_CITY_NAME      [Paris]
    XGEOIP_ZIP_CODE       [75013]
    XGEOIP_LATITUDE       [48.8667000000000]
    XGEOIP_LONGITUDE      [2.3333000000000]
    XGEOIP_AS_NUMBER      [AS12322]
    XGEOIP_AS_NAME        [AS for Proxad/Free ISP]

