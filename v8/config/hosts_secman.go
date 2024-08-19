package config

import (
	"net"
	"stash.delta.sbrf.ru/secman/vault-plugin-helpers/network"
)

func (c *Config) OrderedSRV(service, proto, realm string) (int, map[int]*net.SRV, error) {
	var (
		list []*net.SRV
		err  error
	)

	serviceName := service + "://" + realm
	external := c.External.Discovery
	if external == nil || external.ServiceDiscovery() == nil {
		list, err = network.ServiceDiscoveryOrdered(serviceName, c.External.ExternalResolvers, c.External.ExternalResolversRule, proto)
	} else {
		list, err = external.ServiceDiscovery()(serviceName, c.External.ExternalResolvers, c.External.ExternalResolversRule, proto)
	}
	if err != nil {
		return 0, nil, err
	}
	result := map[int]*net.SRV{}
	for i, srv := range list {
		result[i+1] = srv
	}
	return len(result), result, err
}
