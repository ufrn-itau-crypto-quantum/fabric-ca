module github.com/hyperledger/fabric-ca

go 1.27

toolchain go1.27rc2

require (
	github.com/IBM/idemix v0.0.2-0.20240913182345-72941a5f41cd
	github.com/IBM/idemix/bccsp/types v0.0.0-20240913182345-72941a5f41cd
	github.com/IBM/mathlib v0.0.3-0.20250709075152-a138079496c3
	github.com/casbin/govaluate v1.10.0
	github.com/cloudflare/cfssl v1.6.5
	github.com/felixge/httpsnoop v1.0.4
	github.com/go-kit/kit v0.13.0
	github.com/go-ldap/ldap/v3 v3.4.13
	github.com/go-sql-driver/mysql v1.10.0
	github.com/go-viper/mapstructure/v2 v2.5.0
	github.com/golang/protobuf v1.5.4
	github.com/gorilla/handlers v1.5.2
	github.com/gorilla/mux v1.8.1
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/hyperledger/fabric-amcl v0.0.0-20230602173724-9e02669dceb2
	github.com/hyperledger/fabric-lib-go v1.1.3
	github.com/jinzhu/copier v0.4.0
	github.com/jmoiron/sqlx v1.4.0
	github.com/kisielk/sqlstruct v0.0.0-20210630145711-dae28ed37023
	github.com/lib/pq v1.12.3
	github.com/mattn/go-sqlite3 v1.14.44
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.41.0
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.7.0
	github.com/prometheus/client_golang v1.23.2
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/spf13/viper v1.21.0
	github.com/stretchr/testify v1.11.1
	go.yaml.in/yaml/v4 v4.0.0-rc.4
	golang.org/x/crypto v0.52.0
)

replace github.com/hyperledger/fabric-lib-go => ../fabric-lib-go

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/IBM/idemix/bccsp/schemes/weak-bb v0.0.0-20240612072411-114d281b442d // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/consensys/gnark-crypto v0.19.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/felixge/fgprof v0.9.3 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.6.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/google/certificate-transparency-go v1.1.7 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20260402051712-545e8a4df936 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmhodges/clock v1.2.0 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	github.com/weppos/publicsuffix-go v0.30.0 // indirect
	github.com/zmap/zcrypto v0.0.0-20230310154051-c8b263fd8300 // indirect
	github.com/zmap/zlint/v3 v3.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/grpc v1.81.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.100.1 // indirect
)
