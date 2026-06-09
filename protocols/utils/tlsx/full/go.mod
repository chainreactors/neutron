module github.com/chainreactors/neutron/protocols/utils/tlsx/full

go 1.24.0

toolchain go1.24.3

require (
	github.com/chainreactors/neutron v0.0.0
	github.com/cloudflare/cfssl v1.6.5
)

require (
	github.com/Knetic/govaluate v3.0.0+incompatible // indirect
	github.com/chainreactors/logs v0.0.0-20260508055944-c678762ed15c // indirect
	github.com/google/certificate-transparency-go v1.1.7 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	golang.org/x/crypto v0.19.0 // indirect
)

replace github.com/chainreactors/neutron => ../../../..
