package config

import "stash.delta.sbrf.ru/secman/vault-plugin-helpers/network"

type External struct {
	ExternalResolvers     []network.ResolverIf
	ExternalResolversRule network.ResolverRule
	Discovery             network.Discovery
}
