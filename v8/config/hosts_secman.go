package config

import (
	"net"
	"stash.delta.sbrf.ru/secman/vault-plugin-helpers/network"
)

func (c *Config) OrderedSRV(service, proto, name string) (int, map[int]*net.SRV, error) {
	serviceName := service + "://" + name
	list, err := network.ServiceDiscoveryOrdered(serviceName, c.External.ExternalResolvers, c.External.ExternalResolversRule, proto)
	if err != nil {
		return 0, nil, err
	}
	result := map[int]*net.SRV{}
	for i, srv := range list {
		result[i+1] = srv
	}
	return len(result), result, err
}
