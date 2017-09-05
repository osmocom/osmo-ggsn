OsmoGGSN - Open Source GGSN
===========================

This repository contains a C-language implementation of a GGSN (Gateway
GPRS Support Node), a core network element of ETSI/3GPP cellular
networks such as GPRS, EDGE, UMTS or HSPA.

OsmoGGSN is part of the [Osmocom](https://osmocom.org/) Open Source
Mobile Communications projects, even thogh it was previously developed
by Mondru AB.

Homepage
--------

The official homepage of the project is
https://osmocom.org/projects/openggsn/wiki

GIT Repository
--------------

You can clone from the official osmo-ggsn.git repository using

	git clone git://git.osmocom.org/osmo-ggsn.git

There is a cgit interface at http://git.osmocom.org/osmo-ggsn/

Documentation
-------------

There currently is no other documentation other than the wiki on the
homepage.  It would be great if somebody would work towards a user
manual that can become part of the osmo-gsm-manuals project.

Mailing List
------------

Discussions related to OsmoGGSN are happening on the
osmocom-net-gprs@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/osmocom-net-gprs for
subscription options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards

We us a gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for OsmoGGSN can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-ggsn+status:open


QuickStart
==========

Requirements
------------

*Linux* 
OsmoGGSN was originally developed and tested using Redhat 8.0 and 9.0
and is these days mostly developed on Debian GNU/Linux.  It should run
also on other Linux distributions as well as FreeBSD, but this is
untested. Compilation on Solaris 2.8 has also been verified.

*Tun*
The tun driver is required for proper operation of openggsn. For Linux
kernels later than 2.4.7 the driver is typically included, but might
need to be configured for automatic loading:

1. Add the following line to /etc/modules.conf: alias char-major-10-200 tun 
2. depmod -a


Installation from binary
------------------------

OsmoGGSN is built for common versions of Debian and Ubuntu as part of
the [Osmocom Nightly Builds](https://osmocom.org/projects/cellular-infrastructure/wiki/Nightly_Builds)
project.  If you don't want to do development, it is suggested to simply
use those binary packages, rather than building yourself from source.


Installation from source
------------------------

1. ./configure
2. make
3. make install

You need to be root in order to install the package, but not in order
to compile.


Running
-------

*sgsnemu*
Start the emulator as root using the command:

  sgsnemu -l 10.0.0.50 -r 10.0.0.40 --createif --defaultroute

This will cause the sgsn emulator to bind to local address 10.0.0.50
and connect to the ggsn found at 10.0.0.40. It will first send off an
ECHO_REQUEST message. After this it will attempt to establish a pdp
context. If successful it will create a local interface and set up
routing. Now you should be able to ping through the connection. Use a
network analysator such as ethereal to monitor the traffic.

sgsnemu -h will show a list of available options. 

sgsnemu -c sgsnemu.conf will use sgsnemu.conf as a configuration
file. A sample file is provided in examples/sgsnemu.conf.

*ggsn*
Edit the configuration file ggsn.conf found under openggsn/examples.
Start the ggsn as root using the command:

ggsn --fg -c examples/ggsn.conf -l 10.0.0.40 --statedir ./

This will run the ggsn in foreground using the local interface
10.0.0.40. If you don't have a GSM network available for testing you
can use sgsnemu to test the GGSN.


Support
-------

Please contact the Mailing List above for community-based support.


Features
========

OsmoGGSN is an open source implementation of GPRS Support Nodes
(GSNs). It implements the GPRS tunneling protocol (GTP) version 0 and
version 1.

OsmoGGSN provides 3 components:
 * gtplib
 * osmo-ggsn
 * sgsnemu

*gtplib*
This library contains all functionality relating to the GTP
protocol. Use this library if you want to implement your own
GSN. gtplib supports both GTPv0 (GSM 09.60) and GTPv1 (3GPP
29.060). At the moment no interface documentation is available for
download.

*osmo-ggsn*
The osmo-ggsn implements a Gateway GPRS Support Node. The GGSN is a small
application which is provided in order to test and demonstrate the use
of gtplib. It is fully compliant to the 3GPP standards, but lacks
important functionality such as charging and management. Use this
application as a starting point if you want to build your own GGSN
with your own fancy VPN, management and charging functionality.

*sgsnemu*
This application emulates a Serving GPRS Support Node (SGSN). sgsnemu
enables you to test your 3GPP core network without the need to invest
in a 3G radio access network. An important application of sgsnemu is
the testing of roaming connectivity through a GPRS roaming
exchange. sgsnemu will first attempt to use GTPv1. If unsuccessful it
will fallback to GTPv0.


Required software
=================

Tun
---

Both osmo-ggsn and sgsnemu uses the tun package. You need at least tun
version 1.1. With Linux tun is normally included from kernel version
2.4.7. To configure automatic loading:

1. Add the following line to /etc/modules.conf: alias char-major-10-200 tun 
2. depmod -a

Alternatively you can execute "modprobe tun" on the commandline.

Gengetopt
---------

Gengetopt is required if you want to change the options defined in the
cmdline.ggo source file. You need at least gengetopt version 2.8. If
you are just going to compile the programs you don't need gengetopt.

To use gengetopt for the sgsnemu do the following:
cd sgsnemu
gengetopt < cmdline.ggo --conf-parser

For more information about gengetopt see
http://www.gnu.org/software/gengetopt/gengetopt.html


Compilation and Installation
============================

Please refer to the project homepage


Running osmo-ggsn
=================

Use osmo-ggsn -h for a list of available options. All options available on
the command line can also be given in a configuration file. See
examples/osmo-ggsn.cfg for the format of this file.

Start osmo-ggsn as root using the command:

osmo-ggsn -c examples/osmo-ggsn.cfg

First a tun network interface will be created. In the above example
the network interface address is 192.168.0.0 and the mask is
255.255.255.0. You can check that this interface is up by using
ifconfig.

After tun has been successfully established the ggsn will wait for GTP
create PDP context requests on the local interface
10.0.0.40. Currently all requests are accepted, and no password,
username or APN validation is performed.

When receiving a create PDP context request a dynamic IP address will
be allocated from the address pool determined by --dynip. In the above
example the first allocated address will be 192.168.0.1, followed by
192.168.0.2 and so on. The request is confirmed by sending a create
PDP context response message to the peer (SGSN).

Now IP packets will be forwarded between the tun network interface and
the established GTP tunnel. In order to allow users to access the
external network routing needs to be set up. If private addresses are
used you need to configure network address translation. See the Linux
Networking HOWTO for details.

Remember to enable routing: 

echo 1 > /proc/sys/net/ipv4/ip_forward

If you installed using a binary RPM package it is possible to start
osmo-ggsn by using the Sys 5 script:

/etc/init.d/osmo-ggsn start


Running sgsnemu
===============

Use sgsnemu -h for a list of available options. All options available
on the command line can also be given in a configuration file. See
examples/sgsnemu.conf for the format of this file.

If you want to test a GRX roaming connection you will need to do the
following:

1. Install sgsnemu on a Linux Box. See under installation above.
2. Connect your Linux box with sgsnemu installed to the GPRS core
network. Use the same LAN switch as the one your SGSN is connected
to. You also need a free IP address that can be used by sgsnemu.
3. You need to configure networking in terms of interface address,
subnet mask and default route. See the Linux Networking HOWTO for
details.
4. Launch sgsnemu with something like:

sgsnemu --listen 10.0.0.50 --remote 10.0.0.40 --dns 10.20.38.51 --timelimit 10 --contexts 0 

sgsnemu will print something like the following on the screen:


  Using DNS server:      10.20.38.51 (10.20.38.51)
  Local IP address is:   10.0.0.50 (10.0.0.50)
  Remote IP address is:  10.0.0.40 (10.0.0.40)
  IMSI is:               240011234567890 (0x98765432110042)
  Using APN:             internet
  Using MSISDN:          46702123456

  Initialising GTP library
  OsmoGGSN[1823]: GTP: gtp_newgsn() started
  Done initialising GTP library

  Sending off echo request
  Waiting for response from ggsn........

  Received echo response. Cause value: 0

This is quite good. It means that you managed to send off an echo
request to a remote GGSN, and it was friendly enough to answer you. If
you did not get an echo response it means that something is wrong
either with your setup OR with the GRX connection OR with your roaming
partners connection.

If the above went well you might want to try to establish a PDP
context to the remote GGSN. Note that you should be careful when
establishing PDP contexts using sgsnemu as each established PDP
context will result in a Charge Detail Record (CDR) being generated by
the GGSN. You should use real IMSI and MSISDN from a valid test SIM
card. Otherwise some poor customer might get charged for your
testing. Also note that you are establishing a connection to the Gi
network, so please be carefull not to route internet traffic onto the
GPRS core network! Assuming you know what you are doing:

sgsnemu --listen 10.0.0.50 --remote 10.0.0.40 --dns 10.20.38.51 --timelimit 10 --contexts 1 --apn internet --imsi 240011234567890 --msisdn 46702123456 --createif --defaultroute

sgsnemu will print something like the following on the screen:

  Using DNS server:      10.20.38.51 (10.20.38.51)
  Local IP address is:   10.0.0.50 (10.0.0.50)
  Remote IP address is:  10.0.0.40 (10.0.0.40)
  IMSI is:               240011234567890 (0x98765432110042)
  Using APN:             internet
  Using MSISDN:          46702123456

  Initialising GTP library
  OsmoGGSN[1838]: GTP: gtp_newgsn() started
  Done initialising GTP library

  Sending off echo request
  Setting up PDP context #0
  Waiting for response from ggsn........

  Received echo response. Cause value: 0
  Received create PDP context response. Cause value: 128
  Setting up interface and routing
  /sbin/ifconfig tun0 192.168.0.1
  /sbin/route add -net 192.168.0.0 netmask 255.255.255.0 gw 192.168.0.1


Now a context is established to the remote GGSN. The IP address of the
context is 192.168.0.1. You should be able to ping a known address on
the Gi network of the roaming partner. You should even be able to do
web browsing through the PDP context.

Note however that you probably need to adjust your routing tables, so
that you make sure that all GRX traffic is routed to the GPRS core
network and everything else through the PDP context. The proper way to
do this is to use policy routing. Also note that you are effectively
connecting the same computer to both the Gn and Gi network, so please
be carefull not to route internet traffic onto the GPRS core network
and please protect yourself against hackers! For this reason it is
advised to always use --contexts 0 when testing a live network.

After --timelimit seconds the PDP context is disconnected with the
following messages from sgsnemu:


  Disconnecting PDP context #0
  Received delete PDP context response. Cause value: 128
  Deleting tun interface

