Name:		net-config
Summary:	TIZEN Network Configuration service
Version:	1.1.48
Release:	2
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(aul)
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(tapi)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(bundle)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(eventsystem)
BuildRequires:	pkgconfig(alarm-service)
BuildRequires:	pkgconfig(syspopup-caller)
BuildRequires:	pkgconfig(capi-system-info)
BuildRequires:	pkgconfig(capi-appfw-application)
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	cmake
Requires:		vconf
Requires:		connman
Requires:		systemd
Requires(post):		systemd
Requires(preun):	systemd
Requires(postun):	systemd

%description
TIZEN Network Configuration service

%prep
%setup -q

%build
cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-DTIZEN_WLAN_PASSPOINT=1 \
	-DTIZEN_WLAN_USE_P2P_INTERFACE=1 \
%if 0%{?model_build_feature_wlan_concurrent_mode}
	-DWLAN_CONCURRENT_MODE=1 \
%endif
%if ! 0%{?model_build_feature_wlan_p2p_disable}
	-DTIZEN_P2P_ENABLE=1 \
%endif
%if ! 0%{?model_build_feature_network_tethering_disable}
	-DTIZEN_TETHERING_ENABLE=1 \
%endif
%if "%{profile}" == "tv"
	-DTIZEN_TV=1 \
%endif
%if 0%{?model_build_feature_wlan_wearable} == 1
	-DTIZEN_WEARABLE=1 \
	-DTIZEN_CAPTIVE_PORTAL=1 \
%endif
	.

make %{?_smp_mflags}


%install
%make_install

#Systemd service file
mkdir -p %{buildroot}%{_libdir}/systemd/system/
%if "%{?_lib}" == "lib64"
mkdir -p %{buildroot}%{_unitdir}
%endif

%if "%{profile}" == "tv"
cp resources/usr/lib/systemd/system/net-config_tv.service %{buildroot}%{_libdir}/systemd/system/net-config.service
mkdir -p %{buildroot}%{_libdir}/udev/rules.d/
cp resources/usr/lib/udev/rules.d/99-wifiusb-dev.rules %{buildroot}%{_libdir}/udev/rules.d/99-wifiusb-dev.rules
%else
cp resources/usr/lib/systemd/system/net-config.service %{buildroot}%{_libdir}/systemd/system/net-config.service
%if "%{?_lib}" == "lib64"
cp resources/usr/lib/systemd/system/net-config.service %{buildroot}%{_unitdir}/net-config.service
%endif
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/
ln -s ../net-config.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/net-config.service
%if "%{?_lib}" == "lib64"
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants/
ln -s ../net-config.service %{buildroot}%{_unitdir}/multi-user.target.wants/net-config.service
%endif

mkdir -p %{buildroot}%{_datadir}/dbus-1/system-services/
cp resources/usr/share/dbus-1/system-services/net.netconfig.service %{buildroot}%{_datadir}/dbus-1/system-services/net.netconfig.service

mkdir -p %{buildroot}%{_sysconfdir}/
cp resources/etc/resolv.conf %{buildroot}%{_sysconfdir}/resolv.conf

mkdir -p %{buildroot}%{_sbindir}/
cp resources/usr/sbin/net-config.service %{buildroot}%{_sbindir}/net-config.service

mkdir -p %{buildroot}/usr/dbspace
sqlite3 %{buildroot}/usr/dbspace/.wifi_offload.db < resources/usr/share/wifi_offloading.sql

#DBus DAC (net-config.manifest enables DBus SMACK)
mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d
cp resources/etc/dbus-1/system.d/net-config.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/net-config.conf

#log dump
mkdir -p %{buildroot}/opt/etc/dump.d/module.d/
cp resources/opt/etc/dump.d/module.d/network_log_dump.sh %{buildroot}/opt/etc/dump.d/module.d/network_log_dump.sh
mkdir -p %{buildroot}/opt/var/lib/net-config/
cp resources/opt/etc/dump.d/module.d/network_log_dump.sh %{buildroot}/opt/var/lib/net-config/network_log_dump.sh
cp resources/opt/etc/dump.d/module.d/network_dump.sh %{buildroot}/opt/var/lib/net-config/network_dump.sh

%if 0%{?model_build_feature_wlan_wearable} == 1
#softreset scripts
mkdir -p %{buildroot}/usr/system/RestoreDir/softreset
cp resources/usr/system/RestoreDir/softreset/network_softreset.sh %{buildroot}/usr/system/RestoreDir/softreset/network_softreset.sh
%endif

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE %{buildroot}%{_datadir}/license/net-config

%post

#Network logs
mkdir -p /opt/usr/data/network
chmod 755 /opt/usr/data/network
chsmack -a net-config::logging /opt/usr/data/network

#Add net-config.service to systemd extra default dependency ignore list
mkdir -p %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/
ln -sf %{_libdir}/systemd/system/net-config.service %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/
%if "%{?_lib}" == "lib64"
ln -sf %{_unitdir}/net-config.service %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/
%endif

#systemctl daemon-reload
#systemctl restart net-config.service

%preun
#systemctl stop net-config.service

%postun
#systemctl daemon-reload


%files
%manifest net-config.manifest
%attr(500,root,root) %{_sbindir}/*
%attr(644,root,root) %{_sysconfdir}/resolv.conf
%attr(644,root,root) %{_datadir}/dbus-1/system-services/*
#DBus DAC
%attr(644,root,root) %{_sysconfdir}/dbus-1/system.d/*
%attr(644,root,root) %{_libdir}/systemd/system/net-config.service
%attr(644,root,root) %{_libdir}/systemd/system/multi-user.target.wants/net-config.service
%if "%{?_lib}" == "lib64"
%attr(644,root,root) %{_unitdir}/net-config.service
%attr(644,root,root) %{_unitdir}/multi-user.target.wants/net-config.service
%endif
%{_datadir}/license/net-config
%attr(660,root,root) /usr/dbspace/.wifi_offload.db
%attr(664,root,root) /usr/dbspace/.wifi_offload.db-journal
%attr(500,root,root) /opt/etc/dump.d/module.d/network_log_dump.sh
%attr(500,root,root) /opt/var/lib/net-config/network_log_dump.sh
%attr(500,root,root) /opt/var/lib/net-config/network_dump.sh
%if "%{profile}" == "tv"
%attr(644,root,root) %{_libdir}/udev/rules.d/99-wifiusb-dev.rules
%endif
%if 0%{?model_build_feature_wlan_wearable} == 1
%attr(700,root,root) /usr/system/RestoreDir/softreset/network_softreset.sh

%endif
