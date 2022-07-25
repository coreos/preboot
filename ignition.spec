# Generated by go2rpm 1.3
%if 0%{?fedora}
%bcond_without check
%else
# %%gocheck isn't currently provided on CentOS/RHEL
# https://bugzilla.redhat.com/show_bug.cgi?id=1982298
%bcond_with check
%endif

# https://github.com/coreos/ignition
%global goipath         github.com/coreos/ignition
%global gomodulesmode   GO111MODULE=on
Version:                2.14.0

%gometa

%global golicenses      LICENSE
%global godocs          README.md docs/
%global dracutlibdir %{_prefix}/lib/dracut

Name:           ignition
Release:        3.rhaos4.12%{?dist}
Summary:        First boot installer and configuration tool

# Upstream license specification: Apache-2.0
License:        ASL 2.0
URL:            %{gourl}
Source0:        %{gosource}

BuildRequires: libblkid-devel
BuildRequires: systemd-rpm-macros

# Requires for 'disks' stage
%if 0%{?fedora}
Recommends: btrfs-progs
%endif
Requires: dosfstools
Requires: gdisk
Requires: dracut
Requires: dracut-network

Obsoletes: ignition-dracut < 0.31.0-3

# Generated by `go-mods-to-bundled-provides.py | sort`
Provides: bundled(golang(cloud.google.com/go)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/compute/metadata)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/iam)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/internal)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/internal/optional)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/internal/trace)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/internal/version)) = 0.58.0
Provides: bundled(golang(cloud.google.com/go/storage)) = 0.58.0
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/arn)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/awserr)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/awsutil)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/client)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/client/metadata)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/corehandlers)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/credentials)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/credentials/endpointcreds)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/credentials/processcreds)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/credentials/stscreds)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/csm)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/defaults)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/ec2metadata)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/endpoints)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/request)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/session)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/aws/signer/v4)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/context)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/ini)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/s3err)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/sdkio)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/sdkmath)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/sdkrand)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/sdkuri)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/shareddefaults)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/strings)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/internal/sync/singleflight)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/eventstream)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/eventstream/eventstreamapi)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/json/jsonutil)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/query)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/query/queryutil)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/rest)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/restxml)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/private/protocol/xml/xmlutil)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/service/s3)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/service/s3/internal/arn)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/service/s3/s3iface)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/service/s3/s3manager)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/service/sts)) = 1.30.28
Provides: bundled(golang(github.com/aws/aws-sdk-go/service/sts/stsiface)) = 1.30.28
Provides: bundled(golang(github.com/beevik/etree)) = 1.1.1-0.20200718192613.git4a2f8b9d084c
Provides: bundled(golang(github.com/coreos/go-semver/semver)) = 0.3.0
Provides: bundled(golang(github.com/coreos/go-systemd/v22/dbus)) = 22.0.0
Provides: bundled(golang(github.com/coreos/go-systemd/v22/journal)) = 22.0.0
Provides: bundled(golang(github.com/coreos/go-systemd/v22/unit)) = 22.0.0
Provides: bundled(golang(github.com/coreos/vcontext/json)) = 0.0.0-20211021162308.gitf1dbbca7bef4
Provides: bundled(golang(github.com/coreos/vcontext/path)) = 0.0.0-20211021162308.gitf1dbbca7bef4
Provides: bundled(golang(github.com/coreos/vcontext/report)) = 0.0.0-20211021162308.gitf1dbbca7bef4
Provides: bundled(golang(github.com/coreos/vcontext/tree)) = 0.0.0-20211021162308.gitf1dbbca7bef4
Provides: bundled(golang(github.com/coreos/vcontext/validate)) = 0.0.0-20211021162308.gitf1dbbca7bef4
Provides: bundled(golang(github.com/google/renameio)) = 0.1.0
Provides: bundled(golang(github.com/google/uuid)) = 1.1.1
Provides: bundled(golang(github.com/pin/tftp)) = 2.1.0
Provides: bundled(golang(github.com/pin/tftp/netascii)) = 2.1.0
Provides: bundled(golang(github.com/spf13/pflag)) = 1.0.6-0.20210604193023.gitd5e0c0615ace
Provides: bundled(golang(github.com/stretchr/testify/assert)) = 1.7.0
Provides: bundled(golang(github.com/vincent-petithory/dataurl)) = 1.0.0
Provides: bundled(golang(github.com/vmware/vmw-guestinfo/bdoor)) = 0.0.0-20220317130741.git510905f0efa3
Provides: bundled(golang(github.com/vmware/vmw-guestinfo/message)) = 0.0.0-20220317130741.git510905f0efa3
Provides: bundled(golang(github.com/vmware/vmw-guestinfo/rpcout)) = 0.0.0-20220317130741.git510905f0efa3
Provides: bundled(golang(github.com/vmware/vmw-guestinfo/rpcvmx)) = 0.0.0-20220317130741.git510905f0efa3
Provides: bundled(golang(github.com/vmware/vmw-guestinfo/vmcheck)) = 0.0.0-20220317130741.git510905f0efa3
Provides: bundled(golang(golang.org/x/net/context)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/context/ctxhttp)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/http2)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/http2/hpack)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/http/httpguts)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/http/httpproxy)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/idna)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/internal/timeseries)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/net/trace)) = 0.0.0-20200602114024.git627f9648deb9
Provides: bundled(golang(golang.org/x/oauth2)) = 0.0.0-20200107190931.gitbf48bf16ab8d
Provides: bundled(golang(golang.org/x/oauth2/google)) = 0.0.0-20200107190931.gitbf48bf16ab8d
Provides: bundled(golang(golang.org/x/oauth2/internal)) = 0.0.0-20200107190931.gitbf48bf16ab8d
Provides: bundled(golang(golang.org/x/oauth2/jws)) = 0.0.0-20200107190931.gitbf48bf16ab8d
Provides: bundled(golang(golang.org/x/oauth2/jwt)) = 0.0.0-20200107190931.gitbf48bf16ab8d
Provides: bundled(golang(golang.org/x/sys/internal/unsafeheader)) = 0.0.0-20200610111108.git226ff32320da
Provides: bundled(golang(golang.org/x/sys/unix)) = 0.0.0-20200610111108.git226ff32320da
Provides: bundled(golang(golang.org/x/tools/cmd/goimports)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/analysis)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/analysis/passes/inspect)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/ast/astutil)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/ast/inspector)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/buildutil)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/gcexportdata)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/internal/cgo)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/internal/gcimporter)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/internal/packagesdriver)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/loader)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/packages)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/types/objectpath)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/go/types/typeutil)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/analysisinternal)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/event)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/event/core)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/event/keys)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/event/label)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/fastwalk)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/gocommand)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/gopathwalk)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/imports)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(golang.org/x/tools/internal/packagesinternal)) = 0.0.0-20200610160956.git3e83d1e96d0e
Provides: bundled(golang(google.golang.org/api/googleapi)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/googleapi/transport)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/internal)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/internal/gensupport)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/internal/third_party/uritemplates)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/iterator)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/option)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/option/internaloption)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/storage/v1)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/transport/cert)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/transport/http)) = 0.26.0
Provides: bundled(golang(google.golang.org/api/transport/http/internal/propagation)) = 0.26.0
Provides: bundled(golang(google.golang.org/genproto/googleapis/api/annotations)) = 0.0.0-20200610104632.gita5b850bcf112
Provides: bundled(golang(google.golang.org/genproto/googleapis/iam/v1)) = 0.0.0-20200610104632.gita5b850bcf112
Provides: bundled(golang(google.golang.org/genproto/googleapis/rpc/code)) = 0.0.0-20200610104632.gita5b850bcf112
Provides: bundled(golang(google.golang.org/genproto/googleapis/rpc/status)) = 0.0.0-20200610104632.gita5b850bcf112
Provides: bundled(golang(google.golang.org/genproto/googleapis/type/expr)) = 0.0.0-20200610104632.gita5b850bcf112
Provides: bundled(golang(go.opencensus.io)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/internal)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/internal/tagencoding)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/metric/metricdata)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/metric/metricproducer)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/plugin/ochttp)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/plugin/ochttp/propagation/b3)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/resource)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/stats)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/stats/internal)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/stats/view)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/tag)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/trace)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/trace/internal)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/trace/propagation)) = 0.22.5
Provides: bundled(golang(go.opencensus.io/trace/tracestate)) = 0.22.5

%description
Ignition is a utility used to manipulate systems during the initramfs.
This includes partitioning disks, formatting partitions, writing files
(regular files, systemd units, etc.), and configuring users. On first
boot, Ignition reads its configuration from a source of truth (remote
URL, network metadata service, hypervisor bridge, etc.) and applies
the configuration.

############## validate subpackage ##############

%package validate

Summary:  Validation tool for Ignition configs
License:  ASL 2.0

Conflicts: ignition < 0.31.0-3

%description validate
Ignition is a utility used to manipulate systems during the initramfs.
This includes partitioning disks, formatting partitions, writing files
(regular files, systemd units, etc.), and configuring users. On first
boot, Ignition reads its configuration from a source of truth (remote
URL, network metadata service, hypervisor bridge, etc.) and applies
the configuration.

This package contains a tool for validating Ignition configurations.

############## validate-redistributable subpackage ##############

%if 0%{?fedora}
%package validate-redistributable

Summary:   Statically linked validation tool for Ignition configs
License:   ASL 2.0
BuildArch: noarch

Conflicts: ignition < 0.31.0-3

# In case someone has this subpackage installed, obsolete the old name
# Drop in Fedora 38
Obsoletes:     ignition-validate-nonlinux < 2.13.0-4

%description validate-redistributable
This package contains statically linked Linux, macOS, and Windows
ignition-validate binaries built through cross-compilation. Do not install it.
It is only used for building release binaries to be signed by Fedora release
engineering and uploaded to the Ignition GitHub releases page.
%endif

%prep
%if 0%{?fedora}
%goprep -k
%autopatch -p1
%else
%forgeautosetup -p1
%endif

%build
export LDFLAGS="-X github.com/coreos/ignition/v2/internal/version.Raw=%{version} -X github.com/coreos/ignition/v2/internal/distro.selinuxRelabel=true "
%if 0%{?rhel} || 0%{?centos}
# Need uncompressed debug symbols for debuginfo extraction
LDFLAGS+=' -X github.com/coreos/ignition/v2/internal/distro.writeAuthorizedKeysFragment=false -compressdwarf=false '
%endif
export GOFLAGS="-mod=vendor"

echo "Building ignition..."
%gobuild -o ./ignition internal/main.go

echo "Building ignition-validate..."
%gobuild -o ./ignition-validate validate/main.go

%global gocrossbuild go build -ldflags "${LDFLAGS:-} -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \\n')" -a -v -x

%if 0%{?fedora}
echo "Building statically-linked Linux ignition-validate..."
CGO_ENABLED=0 GOARCH=arm64 GOOS=linux %gocrossbuild -o ./ignition-validate-aarch64-unknown-linux-gnu-static validate/main.go
CGO_ENABLED=0 GOARCH=ppc64le GOOS=linux %gocrossbuild -o ./ignition-validate-ppc64le-unknown-linux-gnu-static validate/main.go
CGO_ENABLED=0 GOARCH=s390x GOOS=linux %gocrossbuild -o ./ignition-validate-s390x-unknown-linux-gnu-static validate/main.go
CGO_ENABLED=0 GOARCH=amd64 GOOS=linux %gocrossbuild -o ./ignition-validate-x86_64-unknown-linux-gnu-static validate/main.go

echo "Building macOS ignition-validate..."
GOARCH=amd64 GOOS=darwin %gocrossbuild -o ./ignition-validate-x86_64-apple-darwin validate/main.go

echo "Building Windows ignition-validate..."
GOARCH=amd64 GOOS=windows %gocrossbuild -o ./ignition-validate-x86_64-pc-windows-gnu.exe validate/main.go
%endif

%install
# dracut modules
install -d -p %{buildroot}/%{dracutlibdir}/modules.d
cp -r dracut/* %{buildroot}/%{dracutlibdir}/modules.d/
install -m 0644 -D -t %{buildroot}/%{_unitdir} systemd/ignition-delete-config.service
install -m 0755 -d %{buildroot}/%{_libexecdir}
ln -sf ../lib/dracut/modules.d/30ignition/ignition %{buildroot}/%{_libexecdir}/ignition-apply
ln -sf ../lib/dracut/modules.d/30ignition/ignition %{buildroot}/%{_libexecdir}/ignition-rmcfg

# ignition
install -d -p %{buildroot}%{_bindir}
install -p -m 0755 ./ignition-validate %{buildroot}%{_bindir}

%if 0%{?fedora}
install -d -p %{buildroot}%{_datadir}/ignition
install -p -m 0644 ./ignition-validate-aarch64-unknown-linux-gnu-static %{buildroot}%{_datadir}/ignition
install -p -m 0644 ./ignition-validate-ppc64le-unknown-linux-gnu-static %{buildroot}%{_datadir}/ignition
install -p -m 0644 ./ignition-validate-s390x-unknown-linux-gnu-static %{buildroot}%{_datadir}/ignition
install -p -m 0644 ./ignition-validate-x86_64-apple-darwin %{buildroot}%{_datadir}/ignition
install -p -m 0644 ./ignition-validate-x86_64-pc-windows-gnu.exe %{buildroot}%{_datadir}/ignition
install -p -m 0644 ./ignition-validate-x86_64-unknown-linux-gnu-static %{buildroot}%{_datadir}/ignition
%endif

# The ignition binary is only for dracut, and is dangerous to run from
# the command line.  Install directly into the dracut module dir.
install -p -m 0755 ./ignition %{buildroot}/%{dracutlibdir}/modules.d/30ignition

%if %{with check}
%check
# Exclude the blackbox tests
%gocheck -t tests
%endif

%files
%license %{golicenses}
%doc %{godocs}
%{dracutlibdir}/modules.d/*
%{_unitdir}/*.service
%{_libexecdir}/ignition-apply
%{_libexecdir}/ignition-rmcfg

%files validate
%doc README.md
%license %{golicenses}
%{_bindir}/ignition-validate

%if 0%{?fedora}
%files validate-redistributable
%license %{golicenses}
%dir %{_datadir}/ignition
%{_datadir}/ignition/ignition-validate-aarch64-unknown-linux-gnu-static
%{_datadir}/ignition/ignition-validate-ppc64le-unknown-linux-gnu-static
%{_datadir}/ignition/ignition-validate-s390x-unknown-linux-gnu-static
%{_datadir}/ignition/ignition-validate-x86_64-apple-darwin
%{_datadir}/ignition/ignition-validate-x86_64-pc-windows-gnu.exe
%{_datadir}/ignition/ignition-validate-x86_64-unknown-linux-gnu-static
%endif

%changelog
* Mon Jul 25 2022 Benjamin Gilbert <bgilbert@redhat.com> - 2.14.0-3.rhaos4.12
- Rebuild with Go 1.18.2

* Tue Jun 28 2022 Aashish Radhakrishnan <aaradhak@redhat.com> - 2.14.0-2.rhaos4.12
- Bumping release 4.12

* Tue Jun 14 2022 Benjamin Gilbert <bgilbert@redhat.com> - 2.14.0-2.rhaos4.11
- Rebuild with newer Go

* Wed May 25 2022 Benjamin Gilbert <bgilbert@redhat.com> - 2.14.0-1.rhaos4.11
- New release
- Add ignition-apply symlink
- Add ignition-rmcfg symlink and ignition-delete-config.service

* Wed Mar 23 2022 Sohan Kunkerkar <skunkerk@redhat.com> - 2.13.0-4.rhaos4.11
- Backport patches for ignition-apply entrypoint
  https://github.com/coreos/ignition/pull/1285
  https://github.com/coreos/ignition/pull/1292

* Sat Jan 29 2022 Benjamin Gilbert <bgilbert@redhat.com> - 2.13.0-3.rhaos4.11
- Rename Fedora -validate-nonlinux subpackage to -validate-redistributable
- Add static Linux binaries to -redistributable
- Fix macro invocation in comment

* Tue Jan 25 2022 Michael Nguyen <mnguyen@redhat.com> - 2.13.0-2.rhaos4.11
- New build for 4.11

* Thu Jan 20 2022 Benjamin Gilbert <bgilbert@redhat.com> - 2.13.0-2.rhaos4.10
- Fix LUKS volume reuse
- Fix patching on Fedora

* Tue Nov 30 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.13.0-1.rhaos4.10
- New release

* Wed Oct 13 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.12.0-3.rhaos4.10
- Add vmw iopl patch reference which got dropped in the previous release
- Avoid reapplying patches
- Move Ignition report to /etc

* Mon Sep 13 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.12.0-2.rhaos4.10
- Redo packaging using go2rpm and conditionalize Fedora-specific configuration
- Disable file fragment writing logic for SSH authorized_keys
- Disable compressdwarf flag to avoid build failures

* Mon Sep 13 2021 Micah Abbott <miabbott@redhat.com> - 2.12.0-1.rhaos4.10
- New build for 4.10

* Mon Aug 9 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.12.0-1.rhaos4.9
- New release

* Thu Jul 29 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.11.0-3.rhaos4.9
- Rebuild to address minor CVE related to golang's crypto/tls package
  https://bugzilla.redhat.com/show_bug.cgi?id=1986042

* Thu Jul  8 2021 Benjamin Gilbert <bgilbert@redhat.com> - 2.11.0-2.rhaos4.9
- Move ignition-firstboot-complete and ignition-setup-user services out of
  package into distro glue

* Fri Jun 25 2021 Benjamin Gilbert <bgilbert@redhat.com> - 2.11.0-1.rhaos4.9
- New release

* Mon Jun 21 2021 Jonathan Lebon <jlebon@redhat.com> - 2.10.1-3.rhaos4.9
- Backport patch for multipath on firstboot
  https://github.com/coreos/ignition/pull/1208
  https://github.com/coreos/fedora-coreos-config/pull/1011
  https://bugzilla.redhat.com/show_bug.cgi?id=1954025

* Wed Jun 9 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.10.1-2.rhaos4.9
- Rebuild to address the CVE related to golang's net/http package
  https://bugzilla.redhat.com/show_bug.cgi?id=1959248

* Mon May 03 2021 Stephen Lowrie <slowrie@redhat.com> - 2.10.1-1.rhaos4.9
- New release

* Fri Feb 05 2021 Benjamin Gilbert <bgilbert@redhat.com> - 2.9.0-3.rhaos4.8
- Drop Git commit hash from Release
- Switch to %%autosetup
- Drop mention of networkd in package description
- Add LICENSE file to base package

* Fri Feb 5 2021 Micah Abbott <miabbott@redhat.com> - 2.9.0-2.rhaos4.8.git1d56dc8
- New build for RHCOS 4.8

* Tue Jan 12 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.9.0-2.rhaos4.7.git1d56dc8
- Fix AWS probing by using the IMDS token URL to ensure that networking is up

* Fri Jan 08 2021 Sohan Kunkerkar <skunkerk@redhat.com> - 2.9.0-1.rhaos4.7.git1d56dc8
- New release
- Update ExclusiveArch and golang BuildRequires for current packaging guidelines

* Fri Dec 04 2020 Sohan Kunkerkar <skunkerk@redhat.com> - 2.8.1-1.rhaos4.7.gitc733d23
- New release

* Mon Nov 30 2020 Sohan Kunkerkar <skunkerk@redhat.com> - 2.8.0-1.rhaos4.7.gitdb4d30d
- New release

* Mon Oct 19 2020 Stephen Lowrie <slowrie@redhat.com> - 2.7.0-1.rhaos4.7.git5be43fd
- New release

* Mon Oct 05 2020 Benjamin Gilbert <bgilbert@redhat.com> - 2.6.0-5.rhaos4.7.git947598e
- Rebuild for 4.7

* Thu Oct 01 2020 Jonathan Lebon <jlebon@redhat.com> - 2.6.0-5.rhaos4.6.git947598e
- Backport patch to defer OpenCensus random ID generation to first use
  https://github.com/census-instrumentation/opencensus-go/pull/1228
  https://bugzilla.redhat.com/show_bug.cgi?id=1882515

* Fri Sep 18 2020 Stephen Lowrie <slowrie@redhat.com> - 2.6.0-4.rhaos4.6.git947598e
- Fix logging interactions with fetch-offline
- Avoid kernel lockdown on VMware when running with secure boot

* Thu Aug 20 2020 Benjamin Gilbert <bgilbert@redhat.com> - 2.6.0-3.rhaos4.6.git947598e
- Write SSH keys directly to authorized_keys, not to fragment file

* Wed Aug 12 2020 Benjamin Gilbert <bgilbert@redhat.com> - 2.6.0-2.rhaos4.6.git947598e
- Fix sector size detection on s390x

* Fri Aug 07 2020 Benjamin Gilbert <bgilbert@redhat.com> - 2.6.0-1.rhaos4.6.git947598e
- New release
- Update license for ignition-dracut merge

* Mon Jul 27 2020 Ben Howard <ben.howard@redhat.com> - 2.5.0-1.rhaos4.6.git0d6f3e5
- Dracut modules are now built from in-tree modules.

* Wed Jul 22 2020 Timothée Ravier <travier@redhat.com> - 2.4.1-1.rhaos4.6.git5260a5b
- New release with ignition-dracut bump (imported from Fedora)

* Tue Jul 21 2020 Timothée Ravier <travier@redhat.com> - 2.3.0-1.rhaos4.6.gitee616d5
- Update to latest spec3x release (imported from Fedora)

* Mon Jun 08 2020 Colin Walters <walters@verbum.org> - 0.35.1-14.rhaos4.6.gitb4d18ad
- Bump to force a re-build for 4.6

* Fri May 22 2020 Sohan Kunkerkar <skunkerk@redhat.com> - 0.35.1-13.rhaos4.6.gitb4d18ad
- Update to latest spec2x to add a CA bundle support

* Tue May 12 2020 Colin Walters <walters@verbum.org> - 0.35.1-12.rhaos4.6.git73ff2d7
- Update to latest spec2x to fix live ISO

* Mon Apr 27 2020 Dusty Mabe <dusty@dustymabe.com> - 0.35.1-11.rhaos4.6.git73ff2d7
- Update to latest ignition-dracut for network fixes
  https://github.com/coreos/ignition-dracut/pull/174

* Sat Apr 18 2020 Colin Walters <walters@verbum.org> - 0.35.1-10.rhaos4.5.git73ff2d7
- Update to latest ignition-dracut for live ISO work

* Fri Apr 17 2020 Colin Walters <walters@verbum.org> - 0.35.1-9.rhaos4.5.git73ff2d7
- Update to latest ignition-dracut for live ISO work

* Fri Apr 17 2020 Colin Walters <walters@verbum.org> - 0.35.1-8.rhaos4.5.git73ff2d7
- Update to latest ignition-dracut for live ISO work

* Thu Apr 16 2020 Colin Walters <walters@verbum.org> - 0.35.1-7.rhaos4.5.git73ff2d7
- Update to latest ignition-dracut for live ISO & virtio dump

* Tue Apr 14 2020 Colin Walters <walters@verbum.org> - 0.35.1-6.rhaos4.5.git73ff2d7
- Update to latest ignition-dracut for live ISO work

* Mon Apr 6 2020 Prashanth Sundararaman <psundara@redhat.com> - 0.35.1-5.rhaos4.5.gite49283b
- Update to latest spec2x commit for blkid fix
    * resource: update Accept header to spec 2.4.0
    * doc/development: remember to bump Accept header during spec bumps
    * blkid: Backport: Explicitly use C int variable for numParts

* Tue Mar 17 2020 Jonathan Lebon <jlebon@redhat.com> - 0.35.1-4.rhaos4.5.gite49283b
- Update to latest spec2x for s390x/ppc64le QEMU support
  https://github.com/coreos/ignition/pull/936

* Thu Mar 12 2020 Colin Walters <walters@verbum.org> - 0.35.1-2.rhaos4.5.git7afbeba
- Bump version numbers to 4.5

* Wed Mar 11 2020 Ben Howard <ben.howard@redhat.com> - 0.35.2-rhaos.4.4.git7afbeba
- Release 0.35.2: update dracut to 7cfc5f9e1692036a688f4693d157d6600dc49bc8
    * Preserve the hostname set from ip=<ARGS> kernel commandline
    * Backport of 'ignition-diskful.target'

* Wed Jan 22 2020 Yu Qi Zhang <jerzhang@redhat.com> - 0.35.0-rhaos.4.4.git7afbeba
- Release of 0.35.0 based on upstream v0.35.0 tag
    * Mark the 2.4.0 config spec as stable
    * No longer accept configs with version 2.4.0-experimental
    * Create new 2.5.0-experimental config spec from 2.4.0
    * Allow specifying HTTP headers when fetching remote resources
- ignition-dracut: align to spec2x commit d5d5663bf7676d070bfd0c3b6f9f78c0a49b68e4
    * Move to ip=dhcp,dhcp6
    * Down bonded interfaces properly

* Wed Dec 11 2019 Ben Howard <ben.howard@redhat.com> - 0.34.0-0-rhaos4.4.git92f874c
- ignition: align to spec2x commit 92f874c194d75ea32a4e63e531db3be4689b4850
    * Release of 0.34.0
    * Bug Fixes:
      - Fix bug where AWS region is not set correctly for fetches from s3
      - Fix bug where empty GPT labels were treated as errors
    * Changes:
      - Ignition now logs the name of the stage it is running
    * Features:
      - Add optional "fetch" stage to cache the rendered config, but not apply
        any of it
      - Add support for aliyun cloud

* Tue Dec 10 2019 Colin Walters <walters@verbum.org> - 0.33.0-14.rhaos4.3.git3625532
- Bump for 4.4

* Wed Dec 04 2019 Allen Bai <abai@redhat.com> - 0.33.0-14.rhaos4.3.git3625532
- Update to latest spec2x
    * firstboot-complete: tell zipl to run

* Thu Nov 07 2019 Colin Walters <walters@verbum.org> - 0.33.0-13.rhaos4.3.git3625532
- Update dracut for complete/subsequent targets

* Thu Nov 07 2019 Jonathan Lebon <jlebon@redhat.com> - 0.33.0-12.rhaos4.3.git3625532
- Update to latest spec2x for:
  https://github.com/coreos/ignition-dracut/pull/135#event-2779552254

* Sat Nov 02 2019 Colin Walters <walters@verbum.org> - 0.33.0-11.rhaos4.3.git3625532
- Revert dracut update

* Thu Oct 31 2019 Colin Walters <walters@verbum.org> - 0.33.0-10.rhaos4.3.git3625532
- Update dracut

* Tue Oct 29 2019 Colin Walters <walters@verbum.org> - 0.33.0-9.rhaos4.3.git3625532
- Update to latest spec2x

* Thu Oct 03 2019 Ben Howard <ben.howard@redhat.com> - 0.33.0-7-rhaos4.3.git3625532
- ignition: align to spec2x commit 362553247e57d7e706c492bb5267eacc34585ca4
    * Backport of `fetch` stage

* Tue Sep 10 2019 Colin Walters <walters@verbum.org> - 0.33.0-4.rhaos4.2.gitc65e95c
- Bump ignition-dracut to help RHCOS rebase on FCOS

* Tue Aug 20 2019 Yu Qi Zhang <jerzhang@redhat.com> - 0.33.0-3.gitc65e95c
- ignition-dracut: align to spec2x commit cc0eee6c9c063b332daf5ef991f4a6b38a79516d
    * persist-ifcfg: fix early exiting of dracut init script

* Thu Aug  8 2019 Steve Milner <smilner@redhat.com> - 0.33.0-2.gitc65e95c
- ignition-dracut: align to spec2x commit 590a413c0e6d46b646a32e326321c151f6903a31
    * persist-ifcfg: Don't persist default ip=dhcp

* Mon Jul 22 2019 Yu Qi Zhang <jerzhang@redhat.com> - 0.33.0-1.gitc65e95c
- ignition: release v0.33.0
    * Fix regression where Ignition would panic if the guestinfo.* keys were
      missing on vmware
    * Create /dev aliases under /run/ignition instead of /
-ignition-dracut: align to spec2x commit cebcaea5dc9f27861e5f6e9ada3a4df094d4413f
    * dracut/30ignition: support `coreos.no_persist_ip`
    * dracut: add 99emergency-timeout module

* Thu May 02 2019 Yu Qi Zhang <jerzhang@redhat.com> - 0.32.0-1.git5941fc0
- ignition: release v0.32.0
    * Add support for http(s) proxies in config v2.4.0-experimental
    * Add `metal` provider with a no-op config fetcher
    * Ignition supports using the kernel command line option
      `ignition.config.url` in addition to `coreos.config.url`
    * Relabel /etc/sub{uid,gid} when adding users with SELinux enabled
    * Add Append() function back to config/vX_Y/ packages
- ignition-dracut: align to spec2x commit a3a7522518a4597fc40586aef283f9cf02aaaf79
    * remove initramfs networking interfaces

* Mon Apr 15 2019 Yu Qi Zhang <jerzhang@redhat.com> - 0.31.0-9.gitbcc520b
- ignition: align to spec2x commit bcc520b1fd43c2f288dab9443b37fe518b039149
    * oem: add metal oem
- ignition-dracut: align to spec2x commit 3728730ef6dc6e779a665140382b2227107e4972
    * ignition-files: always relabel /var on first boot

* Mon Apr 08 2019 Yu Qi Zhang <jerzhang@redhat.com> - 0.31.0-8.gitf59a653
- ignition-dracut: Pull in latest from spec2x branch
    * dracut/30ignition: order services before initrd.target

* Fri Mar 22 2019 Dusty Mabe <dusty@dustymabe.com> - 0.31.0-7.gitf59a653
- ignition-dracut: Pull in latest from spec2x branch
    * grub: support overriding network kcmdline args
- ignition: pull in subuid/subgid files patch from spec2x branch
    * stages/files: Also relabel subuid/subgid files

* Wed Mar 20 2019 Michael Nguyen <mnguyen@redhat.com> - 0.31.0-6.gitf59a653
- Backport patch for supporting guestinfo.ignition.config.data

* Mon Mar 18 2019 Dusty Mabe <dusty@dustymabe.com> - 0.31.0-5.gitf59a653
- Use the spec2x branch of ignition-dracut upstream
- * Since ignition-dracut master has moved to supporting ignition
    spec 3.x we are applying 2.x related fixes to the spec2x
    branch in the ignition-dracut repo.
  * Summary of backports: https://github.com/coreos/ignition-dracut/pull/58

* Mon Mar 18 2019 Benjamin Gilbert <bgilbert@backtick.net> - 0.31.0-4.gitf59a653
- Move dracut modules into main ignition package
- Move ignition binary out of the PATH
- Move ignition-validate into a subpackage
- Include ignition-dracut license file
- Drop developer docs from base package

* Mon Mar 18 2019 Colin Walters <walters@verbum.org> - 0.31.0-3.gitf59a653
- Backport patch for networking

* Mon Mar 04 2019 Dusty Mabe <dusty@dustymabe.com> - 0.31.0-2.gitf59a653
- ignition-dracut: backport patch for finding ignition.firstboot file on UEFI systems
  https://github.com/coreos/ignition-dracut/pull/52

* Wed Feb 20 2019 Andrew Jeddeloh <andrew.jeddeloh@redhat.com> - 0.31.0-1.gitf59a653
- New release 0.31.0

* Fri Feb 15 2019 Dusty Mabe <dusty@dustymabe.com> - 0.30.0-4.git308d7a0
- Bump to ignition-dracut 2c69925
- * support platform configs and user configs in /boot
    ^ https://github.com/coreos/ignition-dracut/pull/43
  * Add ability to parse config.ign file on boot
    ^ https://github.com/coreos/ignition-dracut/pull/42

* Fri Feb 01 2019 Fedora Release Engineering <releng@fedoraproject.org> - 0.30.0-3.git308d7a0
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Mon Jan 28 2019 Dusty Mabe <dusty@dustymabe.com> - 0.30.0-2.git308d7a0
- Bump to ignition-dracut fa7131b
- * 7579b92 journal: add clarifying comment for context
  * a6551f1 Remount /sysroot rw (#38)
  * ignition-firstboot-complete.service: Remount /boot rw

* Sat Dec 15 2018 Benjamin Gilbert <bgilbert@redhat.com> - 0.30.0-1.git308d7a0
- New release 0.30.0

* Fri Dec 14 2018 Michael Nguyen <mnguyen@redhat.com> - 0.29.1-3.gitb1ab0b2
- define gopath for RHEL7

* Tue Dec 11 2018 Dusty Mabe <dusty@dustymabe.com> - 0.29.1-2.gitb1ab0b2
- require golang >= 1.10 and specify architecture list for RHEL7

* Tue Dec 11 2018 Andrew Jeddeloh <andrew.jeddeloh@redhat.com> - 0.29.1-1.gitb1ab0b2
- New release 0.29.1

* Wed Nov 21 2018 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 0.28.0-12.gitf707912
- Rebuild for protobuf 3.6 in rawhide (f30)

* Tue Nov 20 2018 Jonathan Lebon <jonathan@jlebon.com> - 0.28.0-11.git7b83454
- Bump to ignition-dracut 7b83454

* Thu Oct 25 2018 Dusty Mabe <dusty@dustymabe.com> - 0.28.0-10.gitf707912
- Bump to ignition-dracut decf63f
- * 03d8438 30ignition: only instmods if module available

* Thu Oct 25 2018 Dusty Mabe <dusty@dustymabe.com> - 0.28.0-9.gitf707912
- Bump to ignition-dracut 7ee64ca
- * 3ec0b39 remove ignition-remount-sysroot.service files
  * 66335f2 ignition: run files stage at original CL ordering
  * 0301a03 ignition-disks.service: drop Requires=network.target
  * a0bc135 ignition-ask-var-mount.service: use RemainAfterExit=yes
  * ecf5779 module-setup.sh: explicitly install qemu_fw_cfg

* Mon Oct 15 2018 Dusty Mabe <dusty@dustymabe.com> - 0.28.0-8.gitf707912
- Bump to ignition-dracut 4bdfb34
- * 6d0763a module-setup: Make mkfs.btrfs optional

* Wed Oct 10 2018 Jonathan Lebon <jonathan@jlebon.com> - 0.28.0-7.gitf707912
- Backport patch for handling sysctl files correctly
  https://github.com/coreos/coreos-assembler/pull/128
  https://github.com/openshift/machine-config-operator/pull/123

* Wed Sep 26 2018 Dusty Mabe <dusty@dustymabe.com> - 0.28.0-6.gitf707912
- Bump to ignition-dracut c09ce6f
- * ce9f648 30ignition: add support for ignition-disks

* Mon Sep 24 2018 Dusty Mabe <dusty@dustymabe.com> - 0.28.0-5.gitf707912
- Remove requires for btrfs on !fedora
- Bump to ignition-dracut 8c85eb3
- * 26f2396 journal: Don't log to console AND kmsg

* Mon Sep 17 2018 Jonathan Lebon <jonathan@jlebon.com> - 0.28.0-4.gitf707912
- Backport patch for relabeling /var/home on FCOS
  https://github.com/coreos/fedora-coreos-config/issues/2

* Thu Sep 06 2018 Luca Bruno <lucab@fedoraproject.org> - 0.28.0-3.gitf707912
- Add requires for disks stage

* Thu Aug 30 2018 Dusty Mabe <dusty@dustymabe.com> - 0.28.0-2.gitf707912
- Bump to ignition-dracut d056287
- * 3f41219 dracut/ignition: remove CL-legacy udev references
- * 92ef9dd coreos-firstboot-complete: RemainAfterExit=yes

* Thu Aug 30 2018 Andrew Jeddeloh <andrewjeddeloh@redhat.com> - 0.28.0-1.gitf707912
- New release 0.28.0

* Fri Aug 17 2018 Dusty Mabe <dusty@dustymabe.com> - 0.27.0-3.gitcc7ebe0
- Bump to ignition-dracut 56aa514

* Wed Aug 15 2018 Jonathan Lebon <jonathan@jlebon.com> - 0.27.0-2.gitcc7ebe0
- Backport patch for /root relabeling
  https://github.com/coreos/ignition/pull/613

* Fri Aug 10 2018 Jonathan Lebon <jonathan@jlebon.com> - 0.27.0-1.gitcc7ebe0
- New release 0.27.0

* Sat Jul 21 2018 Dusty Mabe <dusty@dustymabe.com> - 0.26.0-0.6.git7610725
- Bump to ignition-dracut d664657

* Fri Jul 13 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.26.0-0.5.git7610725
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Fri Jun 29 2018 Dusty Mabe <dusty@dustymabe.com> - 0.26.0-0.4.git7610725
- Fix building on el7 (install -D not working)

* Fri Jun 29 2018 Dusty Mabe <dusty@dustymabe.com> - 0.26.0-0.3.git7610725
- Bump to ignition-dracut 17a201b

* Tue Jun 26 2018 Dusty Mabe <dusty@dustymabe.com> - 0.26.0-0.2.git7610725
- Rename dustymabe/bootengine upstrem to dustymabe/ignition-dracut

* Thu Jun 21 2018 Dusty Mabe <dusty@dustymabe.com> - 0.26.0-0.1.git7610725
- First package for Fedora

