Name:           udpst
Version:        8.2.0
Release:        2%{?dist}
Summary:        Open Broadband-UDP Speed Test
Group:          Development/Libraries
License:        BSD 3-Clause
URL:            https://github.com/BroadbandForum/obudpst
#git stash create
#git archive --format=tar.gz -o udpst-8.0.0.tar.gz --prefix=udpst-8.0.0/ {stash_id}
Source0:        udpst-%{version}.tar.gz
BuildRequires:  cmake3
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  glibc-headers
BuildRequires:  openssl-devel
BuildRequires:  pandoc
BuildRequires:  gzip

%package server
Requires:       %{name} = %{version}-%{release}
Summary:        Open Broadband-UDP Speed Test Server
Requires:       systemd
Requires:       firewalld

%description
Open Broadband-UDP Speed Test (OB-UDPST) is a client/server software utility to demonstrate one approach of doing IP capacity measurements

%description server
Open Broadband-UDP Speed Test (OB-UDPST) server configuration package

%prep
%setup -q

%build
cmake3 -DCMAKE_INSTALL_PREFIX=/usr .
make %{?_smp_mflags}
pandoc -s -f markdown -t man README.md | gzip > %{name}.1.gz

%install
make install DESTDIR=%{buildroot}
mkdir -p           $RPM_BUILD_ROOT/%{_unitdir}/
cp %{name}.service $RPM_BUILD_ROOT/%{_unitdir}/
mkdir -p           $RPM_BUILD_ROOT/%{_mandir}/man1/
cp %{name}.1.gz    $RPM_BUILD_ROOT/%{_mandir}/man1/

%post server
systemctl daemon-reload
firewall-cmd --permanent --add-port=25000/udp
firewall-cmd --permanent --add-port=32768-60999/udp
firewall-cmd --reload
systemctl restart udpst
systemctl status  udpst --lines=0

%files
%defattr(0644,root,root,-)
%attr(0755,root,root) %{_bindir}/%{name}
%{_mandir}/man1/*

%files server
%attr(0644,root,root) %{_unitdir}/%{name}.service

%changelog
* Mon Aug 26 2024 Michael R. Davis <mrdvt92@yahoo.com> - 8.2.0-1
- Upstream update

* Tue May 09 2023 Michael R. Davis <mrdvt92@yahoo.com> - 8.0.0-1
- Upstream update

* Fri Jun 03 2022 Michael R. Davis <mrdvt92@yahoo.com> - 7.5.0-2
- Added pandoc man file

* Fri Jun 03 2022 Michael R. Davis <mrdvt92@yahoo.com> - 7.5.0-1
- Updated to upstream version 7.5.0

* Mon Apr 04 2022 Michael R. Davis <mrdvt92@yahoo.com> - 7.4.0-1
- Updated to upstream version 7.4.0
- Fixed client RPM only install

* Thu Mar 18 2021 Michael R. Davis <mrdvt92@yahoo.com> - 7.1.0-3
- Split out server package and added firewall-cmd to open ports

* Thu Mar 18 2021 Michael R. Davis <mrdvt92@yahoo.com> - 7.1.0-2
- Added service file

* Thu Mar 18 2021 Michael R. Davis <mrdvt92@yahoo.com> - 7.1.0-1
- Original spec file
