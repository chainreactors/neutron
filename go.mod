module github.com/chainreactors/neutron

go 1.11

require (
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2
	github.com/chainreactors/logs v0.0.0-20250312104344-9f30fa69d3c9
	github.com/chainreactors/words v0.0.0-00010101000000-000000000000
	github.com/hashicorp/go-version v1.6.0
	github.com/spaolacci/murmur3 v1.1.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/exp v0.0.0-20240222234643-814bf88cf225
)

replace github.com/chainreactors/words => /mnt/chainreactors/words

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/invopop/jsonschema v0.13.0
	gopkg.in/yaml.v3 v3.0.1
)
