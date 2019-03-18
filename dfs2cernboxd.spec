# 
# dfs2cernboxd spec file
#

Name: dfs2cernboxd
Summary: DFS to CERNBox migration daemon
Version: 0.0.4
Release: 1%{?dist}
License: AGPLv3
BuildRoot: %{_tmppath}/%{name}-buildroot
Group: CERN-IT/ST
BuildArch: x86_64
Source: %{name}-%{version}.tar.gz

%description
This RPM provides a daemon to help in the migration from DFS to CERNBox

# Don't do any post-install weirdness, especially compiling .py files
%define __os_install_post %{nil}

%prep
%setup -n %{name}-%{version}

%install
# server versioning

# installation
rm -rf %buildroot/
mkdir -p %buildroot/usr/local/bin
mkdir -p %buildroot/etc/dfs2cernboxd
mkdir -p %buildroot/etc/logrotate.d
mkdir -p %buildroot/usr/lib/systemd/system
mkdir -p %buildroot/var/log/dfs2cernboxd
install -m 755 dfs2cernboxd	     %buildroot/usr/local/bin/dfs2cernboxd
install -m 644 dfs2cernboxd.service    %buildroot/usr/lib/systemd/system/dfs2cernboxd.service
install -m 644 dfs2cernboxd.yaml       %buildroot/etc/dfs2cernboxd/dfs2cernboxd.yaml
install -m 644 dfs2cernboxd.logrotate  %buildroot/etc/logrotate.d/dfs2cernboxd

%clean
rm -rf %buildroot/

%preun

%post

%files
%defattr(-,root,root,-)
/etc/dfs2cernboxd
/etc/logrotate.d/dfs2cernboxd
/var/log/dfs2cernboxd
/usr/lib/systemd/system/dfs2cernboxd.service
/usr/local/bin/*
%config(noreplace) /etc/dfs2cernboxd/dfs2cernboxd.yaml


%changelog
* Mon Mar 18 2019 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.4
- Add case-insentive check for DFS folders: Documents, documents, DOCUMENTS
* Tue Dec 18 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.3
- Fix systemd configuration file
* Mon Sep 21 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.2
* Thu Aug 30 2018 Hugo Gonzalez Labrador <hugo.gonzalez.labrador@cern.ch> 0.0.1
- First version
