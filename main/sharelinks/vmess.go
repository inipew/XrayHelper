package sharelinks

import "XrayHelper/main/errors"

type Vmess struct{}

func (this *Vmess) GetNodeInfo() string {
	// TODO
	return ""
}

func (this *Vmess) ToOutoundWithTag(tag string) interface{} {
	// TODO
	return ""
}

func newVmessShareLink(vmessUrl string) (ShareLink, error) {
	return nil, errors.New("TODO").WithPrefix("vmess")
}