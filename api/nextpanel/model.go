package nextpanel

import "encoding/json"

// NodeInfoResponse is the response of node
type NodeInfoResponse struct {
	SpeedLimit   float64         `json:"speed_limit"`
	TrafficRate  float64         `json:"traffic_rate"`
	CustomConfig json.RawMessage `json:"custom_config"`
}

type CustomConfig struct {
	Port          string          `json:"port"`
	Host          string          `json:"host"`
	Method        string          `json:"method"`
	Tls           string          `json:"tls"`
	EnableVless   string          `json:"enable_vless"`
	Network       string          `json:"network"`
	Security      string          `json:"security"`
	Path          string          `json:"path"`
	VerifyCert    bool            `json:"verify_cert"`
	Obfs          string          `json:"obfs"`
	Header        json.RawMessage `json:"header"`
	AllowInsecure string          `json:"allow_insecure"`
	Servicename   string          `json:"servicename"`
	EnableXtls    string          `json:"enable_xtls"`
	Flow          string          `json:"flow"`
	EnableReality bool            `json:"enable_reality"`
	RealityOpts   *RealityConfig  `json:"reality_opts"`
}

// UserResponse is the response of user
type UserResponse struct {
	Id          int     `json:"uid"`
	Passwd      string  `json:"passwd"`
	Method      string  `json:"method"`
	SpeedLimit  float64 `json:"speed_limit"`
	DeviceLimit int     `json:"device_limit"`
	Uuid        string  `json:"uuid"`
	AliveIp     int     `json:"alive_ip"`
}

// SystemLoad is the data structure of system load
type SystemLoad struct {
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
}

// OnlineUser is the data structure of online user
type OnlineUser struct {
	Uid int    `json:"uid"`
	Ip  string `json:"ip"`
}

// UserTraffic is the data structure of traffic
type UserTraffic struct {
	Uid      int    `json:"uid"`
	Email    string `json:"email"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

// RuleItem is data structure of node rule
type RuleItem struct {
	Id      int    `json:"id"`
	Pattern string `json:"regexp"`
}

type IllegalItem struct {
	RuleID int `json:"rule_id"`
	Uid    int `json:"uid"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

type RealityConfig struct {
	Dest             string   `json:"dest,omitempty"`
	ProxyProtocolVer uint64   `json:"proxy_protocol_ver,omitempty"`
	ServerNames      []string `json:"server_names,omitempty"`
	PrivateKey       string   `json:"private_key,omitempty"`
	MinClientVer     string   `json:"min_client_ver,omitempty"`
	MaxClientVer     string   `json:"max_client_ver,omitempty"`
	MaxTimeDiff      uint64   `json:"max_time_diff,omitempty"`
	ShortIds         []string `json:"short_ids,omitempty"`
}
