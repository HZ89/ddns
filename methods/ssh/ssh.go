package ssh

import "dnspod-client/methods/api"


type ssh struct {}

func (s *ssh)Address() (string, error){return "", nil}

func New(o string)api.AddressGetter{return &ssh{}}