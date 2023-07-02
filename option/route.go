package option

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type RouteOptions struct {
	GeoIP               *GeoIPOptions       `json:"geoip,omitempty"`
	Geosite             *GeositeOptions     `json:"geosite,omitempty"`
	Rules               []Rule              `json:"rules,omitempty"`
	RuleSet             []RuleSet           `json:"rule_set,omitempty"`
	Final               string              `json:"final,omitempty"`
	FindProcess         bool                `json:"find_process,omitempty"`
	AutoDetectInterface bool                `json:"auto_detect_interface,omitempty"`
	OverrideAndroidVPN  bool                `json:"override_android_vpn,omitempty"`
	DefaultInterface    string              `json:"default_interface,omitempty"`
	DefaultMark         uint32              `json:"default_mark,omitempty"`
	DomainStrategy      RouteDomainStrategy `json:"domain_strategy,omitempty"`
}

type GeoIPOptions struct {
	Path           string `json:"path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
}

type GeositeOptions struct {
	Path           string `json:"path,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
}

type RouteDomainStrategy uint8

const (
	RouteDomainStrategyAsIS RouteDomainStrategy = iota
	RouteDomainStrategyIPOnDemand
	RouteDomainStrategyIPIfNonMatch
)

func (s RouteDomainStrategy) MarshalJSON() ([]byte, error) {
	var value string
	switch s {
	case RouteDomainStrategyAsIS:
		value = ""
		// value = "AsIS"
	case RouteDomainStrategyIPOnDemand:
		value = "ip_on_demand"
	case RouteDomainStrategyIPIfNonMatch:
		value = "ip_if_non_match"
	default:
		return nil, E.New("unknown domain strategy: ", s)
	}
	return json.Marshal(value)
}

func (s *RouteDomainStrategy) UnmarshalJSON(bytes []byte) error {
	var value string
	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return err
	}
	switch value {
	case "", "as_is":
		*s = RouteDomainStrategy(RouteDomainStrategyAsIS)
	case "ip_on_demand":
		*s = RouteDomainStrategy(RouteDomainStrategyIPOnDemand)
	case "ip_if_non_match":
		*s = RouteDomainStrategy(RouteDomainStrategyIPIfNonMatch)
	default:
		return E.New("unknown domain strategy: ", value)
	}
	return nil
}
