#
# spec file for package osmo-ggsn
#
# Copyright (c) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

## Disable LTO for now since it breaks compilation of the tests
## https://osmocom.org/issues/4114
%define _lto_cflags %{nil}


Name:           osmo-ggsn
Version:        1.5.0.31
Release:        0
Summary:        GPRS Support Node
License:        GPL-2.0-only AND LGPL-2.1-or-later
Group:          Productivity/Telephony/Servers
URL:            https://osmocom.org/projects/openggsn/wiki/OsmoGGSN
Source:         %{name}-%{version}.tar.xz
BuildRequires:  libtool >= 2
BuildRequires:  pkgconfig >= 0.20
BuildRequires:  systemd-rpm-macros
BuildRequires:  pkgconfig(libgtpnl) >= 1.0.0
BuildRequires:  pkgconfig(libmnl) >= 1.0.3
BuildRequires:  pkgconfig(libosmocore) >= 1.1.0
BuildRequires:  pkgconfig(libosmoctrl) >= 1.1.0
BuildRequires:  pkgconfig(libosmovty) >= 1.1.0
Obsoletes:      openggsn
%{?systemd_requires}

%description
Osmo-GGSN is a C-language implementation of a GGSN (Gateway GPRS
Support Node), a core network element of ETSI/3GPP cellular networks
such as GPRS, EDGE, UMTS or HSPA.

%package -n libgtp6
Summary:        Library implementing GTP between SGSN and GGSN
License:        GPL-2.0-only
Group:          System/Libraries

%description -n libgtp6
libgtp implements the GPRS Tunneling Protocol between SGSN and GGSN.

%package -n libgtp-devel
Summary:        Development files for the GTP library
License:        GPL-2.0-only
Group:          Development/Libraries/C and C++
Requires:       libgtp6 = %{version}

%description -n libgtp-devel
libgtp implements the GPRS Tunneling Protocol between SGSN and GGSN.

This subpackage contains libraries and header files for developing
applications that want to make use of libgtp.

%prep
%setup -q

%build
echo "%{version}" >.tarball-version
autoreconf -fi
%configure \
  --disable-static \
  --docdir="%{_docdir}/%{name}" \
  --with-systemdsystemunitdir=%{_unitdir} \
  --includedir="%{_includedir}/%{name}"
make %{?_smp_mflags} V=1

%install
%make_install
find %{buildroot} -type f -name "*.la" -delete -print

%check
make %{?_smp_mflags} check || (find . -name testsuite.log -exec cat {} +)

%pre
%service_add_pre %{name}.service

%post
%service_add_post %{name}.service

%preun
%service_del_preun %{name}.service

%postun
%service_del_postun %{name}.service

%post   -n libgtp6 -p /sbin/ldconfig
%postun -n libgtp6 -p /sbin/ldconfig

%files
%license COPYING
%doc AUTHORS README.md
%{_bindir}/osmo-ggsn
%{_bindir}/sgsnemu
%{_mandir}/man8/osmo-ggsn.8%{?ext_man}
%{_mandir}/man8/sgsnemu.8%{?ext_man}
%{_unitdir}/%{name}.service
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/osmo-ggsn.cfg
%dir %{_sysconfdir}/osmocom
%config(noreplace) %{_sysconfdir}/osmocom/osmo-ggsn.cfg

%files -n libgtp6
%{_libdir}/libgtp.so.6*

%files -n libgtp-devel
%{_includedir}/%{name}/
%{_libdir}/libgtp.so
%{_libdir}/pkgconfig/libgtp.pc

%changelog
