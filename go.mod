module github.com/navidrome/navidrome

go 1.24.4

// Fork to fix https://github.com/navidrome/navidrome/pull/3254
replace github.com/dhowden/tag v0.0.0-20240417053706-3d75831295e8 => github.com/deluan/tag v0.0.0-20241002021117-dfe5e6ea396d

require (
	github.com/Masterminds/squirrel v1.5.4
	github.com/RaveNoX/go-jsoncommentstrip v1.0.0
	github.com/andybalholm/cascadia v1.3.3
	github.com/bmatcuk/doublestar/v4 v4.8.1
	github.com/bradleyjkemp/cupaloy/v2 v2.8.0
	github.com/coreos/go-oidc/v3 v3.14.1
	github.com/deluan/rest v0.0.0-20211102003136-6260bc399cbf
	github.com/deluan/sanitize v0.0.0-20241120162836-fdfd8fdfaa55
	github.com/dexterlb/mpvipc v0.0.0-20241005113212-7cdefca0e933
	github.com/dhowden/tag v0.0.0-20240417053706-3d75831295e8
	github.com/disintegration/imaging v1.6.2
	github.com/djherbis/atime v1.1.0
	github.com/djherbis/fscache v0.10.2-0.20231127215153-442a07e326c4
	github.com/djherbis/stream v1.4.0
	github.com/djherbis/times v1.6.0
	github.com/dustin/go-humanize v1.0.1
	github.com/fatih/structs v1.1.0
	github.com/go-chi/chi/v5 v5.2.1
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/httprate v0.15.0
	github.com/go-chi/jwtauth/v5 v5.3.3
	github.com/go-viper/encoding/ini v0.1.1
	github.com/gohugoio/hashstructure v0.5.0
	github.com/google/go-pipeline v0.0.0-20230411140531-6cbedfc1d3fc
	github.com/google/uuid v1.6.0
	github.com/google/wire v0.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/jellydator/ttlcache/v3 v3.3.0
	github.com/kardianos/service v1.2.2
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/knqyf263/go-plugin v0.9.0
	github.com/kr/pretty v0.3.1
	github.com/lestrrat-go/jwx/v2 v2.1.6
	github.com/matoous/go-nanoid/v2 v2.1.0
	github.com/mattn/go-sqlite3 v1.14.28
	github.com/microcosm-cc/bluemonday v1.0.27
	github.com/mileusna/useragent v1.3.5
	github.com/onsi/ginkgo/v2 v2.23.4
	github.com/onsi/gomega v1.37.0
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/pocketbase/dbx v1.11.0
	github.com/pressly/goose/v3 v3.24.3
	github.com/prometheus/client_golang v1.22.0
	github.com/rjeczalik/notify v0.9.3
	github.com/robfig/cron/v3 v3.0.1
	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	github.com/tetratelabs/wazero v1.9.0
	github.com/unrolled/secure v1.17.0
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1
	go.uber.org/goleak v1.3.0
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6
	golang.org/x/image v0.27.0
	golang.org/x/net v0.40.0
	golang.org/x/oauth2 v0.30.0
	golang.org/x/sync v0.14.0
	golang.org/x/sys v0.33.0
	golang.org/x/text v0.25.0
	golang.org/x/time v0.11.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
)

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/atombender/go-jsonschema v0.20.0 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/reflex v0.3.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/creack/pty v1.1.11 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.17.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20250501235452-c0086092b71a // indirect
	github.com/google/subcommands v1.2.0 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ogier/pflag v0.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/sanity-io/litter v1.5.8 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	github.com/sosodev/duration v1.3.1 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.8.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce // indirect
)

tool (
	github.com/atombender/go-jsonschema
	github.com/cespare/reflex
	github.com/google/wire/cmd/wire
	github.com/onsi/ginkgo/v2/ginkgo
	golang.org/x/tools/cmd/goimports
)
