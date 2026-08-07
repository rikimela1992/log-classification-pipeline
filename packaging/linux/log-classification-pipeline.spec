Name:           log-classification-pipeline
Version:        0.1.0
Release:        0.alpha.1%{?dist}
Summary:        Alpha local fail-closed log classification workspace
License:        MIT
URL:            https://github.com/rikimela1992/log-classification-pipeline
Source0:        log-classification-pipeline-stage.tar.gz
BuildArch:      x86_64
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Self-contained alpha browser workspace and CLI for bounded, fail-closed log
classification. This package is not production-ready and includes no model.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%install
mkdir -p %{buildroot}
cp -a stage/. %{buildroot}/

%pre
getent group log-classify >/dev/null || groupadd --system log-classify
getent passwd log-classify >/dev/null || useradd --system --gid log-classify --home-dir /var/lib/log-classification-pipeline --shell /sbin/nologin log-classify

%post
chown log-classify:log-classify /var/lib/log-classification-pipeline
systemctl daemon-reload >/dev/null 2>&1 || true

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now log-classification-pipeline.service >/dev/null 2>&1 || true
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || true

%files
%license /usr/share/doc/log-classification-pipeline/LICENSE
%doc /usr/share/doc/log-classification-pipeline/README.md
%doc /usr/share/doc/log-classification-pipeline/WEB_WORKSPACE.md
%doc /usr/share/doc/log-classification-pipeline/PYTHON_LICENSE.txt
%doc /usr/share/doc/log-classification-pipeline/THIRD_PARTY_PYTHON_LICENSES.fedora.json
%doc /usr/share/doc/log-classification-pipeline/log-classification-pipeline-0.1.0-alpha.1.fedora.bundle.spdx.json
%doc /usr/share/doc/log-classification-pipeline/log-classification-pipeline-0.1.0-alpha.1.fedora.sbom.cdx.json
%doc /usr/share/doc/log-classification-pipeline/native-licenses-fedora41
/usr/bin/log-classification-pipeline
/usr/lib/log-classification-pipeline
/usr/lib/systemd/system/log-classification-pipeline.service
/usr/share/applications/log-classification-pipeline.desktop
/usr/share/icons/hicolor/scalable/apps/log-classification-pipeline.svg
/usr/share/metainfo/io.github.rikimela1992.log-classification-pipeline.metainfo.xml
%attr(0700,log-classify,log-classify) %dir /var/lib/log-classification-pipeline

%changelog
* Fri Aug 07 2026 Riccardo Melini - 0.1.0-0.alpha.1
- Initial alpha package
