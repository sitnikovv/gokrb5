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

	// Если callback на внешнюю функцию исследования не указан, будем использовать оригинальное поведение
	if external == nil || external.ServiceDiscovery() == nil {
		return dnsutils.OrderedSRV("kerberos", proto, realm)
	}

	// Вызываем внешнюю функцию для исследования сети
	list, err = external.ServiceDiscovery()(serviceName, c.External.ExternalResolvers, c.External.ExternalResolversRule, proto)
	if err != nil {
		return 0, nil, err
	}

	// На основе полученных данных формируем выходной результат
	result := map[int]*net.SRV{}
	for i, srv := range list {
		result[i+1] = srv
	}

	return len(result), result, err
}
