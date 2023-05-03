package api

type AddressGetter interface {
	Address() (string, error)
}