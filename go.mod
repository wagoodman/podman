module github.com/containers/podman/v2

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/adrg/xdg v0.2.1
	github.com/anchore/grype v0.2.0
	github.com/anchore/syft v0.4.0
	github.com/blang/semver v3.5.1+incompatible
	github.com/buger/goterm v0.0.0-20181115115552-c206103e1f37
	github.com/checkpoint-restore/go-criu v0.0.0-20190109184317-bdb7599cd87b
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.7
	github.com/containers/buildah v1.17.0
	github.com/containers/common v0.26.3
	github.com/containers/conmon v2.0.20+incompatible
	github.com/containers/image/v5 v5.7.0
	github.com/containers/psgo v1.5.1
	github.com/containers/storage v1.23.8
	github.com/coreos/go-systemd/v22 v22.1.0
	github.com/cri-o/ocicni v0.2.0
	github.com/cyphar/filepath-securejoin v0.2.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v17.12.0-ce-rc1.0.20201020191947-73dc6a680cdd+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/ghodss/yaml v1.0.0
	github.com/godbus/dbus/v5 v5.0.3
	github.com/google/shlex v0.0.0-20181106134648-c34317bd91bf
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/schema v1.2.0
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hpcloud/tail v1.0.0
	github.com/json-iterator/go v1.1.10
	github.com/moby/term v0.0.0-20200915141129-7f0af18e79f2
	github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/opencontainers/runc v1.0.0-rc91.0.20200708210054-ce54a9d4d79b
	github.com/opencontainers/runtime-spec v1.0.3-0.20200817204227-f9c09b4ea1df
	github.com/opencontainers/runtime-tools v0.9.0
	github.com/opencontainers/selinux v1.6.0
	github.com/opentracing/opentracing-go v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/rootless-containers/rootlesskit v0.10.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/uber/jaeger-client-go v2.25.0+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/varlink/go v0.0.0-20190502142041-0f1d566d194b
	github.com/vishvananda/netlink v1.1.0
	go.etcd.io/bbolt v1.3.5
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/sys v0.0.0-20201018230417-eeed37f84f13
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.17.4
)

replace github.com/Microsoft/go-winio v0.4.15-0.20200908182639-5b44b70ab3ab => github.com/Microsoft/go-winio v0.4.14
