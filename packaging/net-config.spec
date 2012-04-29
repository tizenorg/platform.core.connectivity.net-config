#sbs-git:pkgs/n/net-config

Name:       net-config
Summary:    TIZEN Network Configuration Module
Version:    0.1.74
Release:    1
Group:      System/Network
License:    Apache License Version 2.0
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(tapi)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(wifi-direct)
BuildRequires:  pkgconfig(syspopup-caller)

%description
TIZEN Network Configuration Module


%prep
%setup -q

%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/usr/share/dbus-1/services
cp resources/usr/share/dbus-1/services/net.netconfig.service %{buildroot}/usr/share/dbus-1/services/net.netconfig.service
mkdir -p %{buildroot}/usr/etc/dbus-1/system.d
cp resources/usr/etc/dbus-1/system.d/net-config.conf %{buildroot}/usr/etc/dbus-1/system.d/net-config.conf
mkdir -p %{buildroot}/opt/etc
cp resources/opt/etc/resolv.conf %{buildroot}/opt/etc/resolv.conf
mkdir -p %{buildroot}/etc/rc.d/init.d
cp resources/etc/rc.d/init.d/net-config %{buildroot}/etc/rc.d/init.d/net-config
mkdir -p %{buildroot}/etc/rc.d/rc3.d
ln -s ../init.d/net-config %{buildroot}/etc/rc.d/rc3.d/S60net-config
mkdir -p %{buildroot}/etc/rc.d/rc5.d
ln -s ../init.d/net-config %{buildroot}/etc/rc.d/rc5.d/S60net-config


%post

vconftool set -t int memory/dnet/state 0 -i
vconftool set -t int memory/wifi/state 0 -i
vconftool set -t int memory/wifi/strength 0 -i

vconftool set -t int memory/dnet/cellular 0 -i
vconftool set -t int memory/dnet/wifi 0 -i
vconftool set -t int memory/dnet/network_config 0 -i
vconftool set -t int memory/dnet/status 0 -i
vconftool set -t string memory/dnet/ip "" -i
vconftool set -t string memory/dnet/proxy "" -i

vconftool set -t string memory/wifi/connected_ap_name "" -i

vconftool set -t string db/wifi/bssid_address ""

#Default Call Statistics
vconftool set -t int db/dnet/statistics/cellular/totalsnt "0"
vconftool set -t int db/dnet/statistics/cellular/totalrcv "0"
vconftool set -t int db/dnet/statistics/cellular/lastsnt "0"
vconftool set -t int db/dnet/statistics/cellular/lastrcv "0"
vconftool set -t int db/dnet/statistics/wifi/totalsnt "0"
vconftool set -t int db/dnet/statistics/wifi/totalrcv "0"
vconftool set -t int db/dnet/statistics/wifi/lastsnt "0"
vconftool set -t int db/dnet/statistics/wifi/lastrcv "0"
vconftool set -t int db/wifi/LastPowerOnState "0"

#Change File Permission
#Resource
chmod 644 /opt/etc/resolv.conf

%postun


%files
%defattr(-,root,root,-)
%{_sbindir}/*
%{_datadir}/dbus-1/services/*
/opt/etc/resolv.conf
%{_prefix}/etc/dbus-1/system.d/*
%{_sysconfdir}/rc.d/init.d/net-config
%{_sysconfdir}/rc.d/rc3.d/S60net-config
%{_sysconfdir}/rc.d/rc5.d/S60net-config
