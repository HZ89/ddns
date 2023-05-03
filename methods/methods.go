package methods

import (
	"fmt"

	"dnspod-client/methods/api"
	"dnspod-client/methods/ssh"

	"k8s.io/apimachinery/pkg/util/sets"
)

var methodList = map[string]func(string) api.AddressGetter{
	"ssh": ssh.New,
}

func New(n string) (api.AddressGetter, error) {
	fn, exist := methodList[n]
	if !exist {
		return nil, fmt.Errorf("%s not exists", n)
	}
	return fn(n), nil
}

func Avaliable() sets.Set[string] {
	res := sets.New[string]()
	for k := range methodList {
		res.Insert(k)
	}
	return res
}
