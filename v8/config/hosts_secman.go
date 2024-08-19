package config

import (
	"github.com/jcmturner/dnsutils/v2"
	"net"
)

func (c *Config) OrderedSRV(service, proto, realm string) (int, map[int]*net.SRV, error) {
	var (
		list []*net.SRV
		err  error
	)

	serviceName := service + "://" + realm
	external := c.External.Discovery
	if external == nil || external.ServiceDiscovery() == nil {
		return dnsutils.OrderedSRV("kerberos", proto, realm)
	}
	if discovery := external.ServiceDiscovery(); discovery != nil {
		list, err = discovery(serviceName, c.External.ExternalResolvers, c.External.ExternalResolversRule, proto)
		if err != nil {
			return 0, nil, err
		}
	}
	if order := external.Order(); order != nil {
		list = order(list)
	}
	if precessing := external.PostProcessing(); precessing != nil {
		list, err = precessing(list)
		if err != nil {
			return 0, nil, err
		}
	}
	result := map[int]*net.SRV{}
	for i, srv := range list {
		result[i+1] = srv
	}
	return len(result), result, err
}
