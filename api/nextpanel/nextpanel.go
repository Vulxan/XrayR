package nextpanel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"

	"github.com/XrayR-project/XrayR/api"
)

type APIClient struct {
	client           *resty.Client
	APIHost          string
	NodeID           int
	Key              string
	NodeType         string
	EnableVless      bool
	VlessFlow        string
	SpeedLimit       float64
	DeviceLimit      int
	LocalRuleList    []api.DetectRule
	LastReportOnline map[int]int
	access           sync.Mutex
	eTags            map[string]string
}

// New create api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	client.SetQueryParam("token", apiConfig.Key)
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	return &APIClient{
		client:           client,
		APIHost:          apiConfig.APIHost,
		NodeID:           apiConfig.NodeID,
		Key:              apiConfig.Key,
		NodeType:         apiConfig.NodeType,
		EnableVless:      apiConfig.EnableVless,
		VlessFlow:        apiConfig.VlessFlow,
		SpeedLimit:       apiConfig.SpeedLimit,
		DeviceLimit:      apiConfig.DeviceLimit,
		LocalRuleList:    localRuleList,
		LastReportOnline: make(map[int]int),
		eTags:            make(map[string]string),
	}
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Printf("Error when closing file: %s", err)
			}
		}(file)

		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) ([]byte, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	body := res.Body()

	if res.StatusCode() != 200 {
		return nil, fmt.Errorf("request %s failed with code %d: %s, %v", c.assembleURL(path), res.StatusCode(), string(body), err)
	}
	// response := res.Result().(*Response)

	// if response.Status != 0 {
	// 	res, _ := json.Marshal(&response)
	// 	return nil, fmt.Errorf("status %s invalid", string(res))
	// }
	return body, nil
}

// GetNodeInfo will pull NodeInfo Config
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := fmt.Sprintf("/api/node/%d/", c.NodeID)
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	nodeInfoResponse := new(NodeInfoResponse)

	if err := json.Unmarshal(response, nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(nodeInfoResponse), err)
	}

	nodeInfo, err = c.ParseNodeInfo(nodeInfoResponse)

	if err != nil {
		res, _ := json.Marshal(nodeInfoResponse)
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

// ParseNodeInfo parse the response for the given node info format
func (c *APIClient) ParseNodeInfo(nodeInfoResponse *NodeInfoResponse) (*api.NodeInfo, error) {
	var (
		speedLimit             uint64 = 0
		enableTLS, enableVless bool
		alterID                uint16 = 0
		transportProtocol      string
	)

	// Check if custom_config is null
	if len(nodeInfoResponse.CustomConfig) == 0 {
		return nil, errors.New("custom_config is empty, disable custom config")
	}

	nodeConfig := new(CustomConfig)
	err := json.Unmarshal(nodeInfoResponse.CustomConfig, nodeConfig)
	if err != nil {
		return nil, fmt.Errorf("custom_config format error: %v", err)
	}

	if c.SpeedLimit > 0 {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((nodeInfoResponse.SpeedLimit * 1000000) / 8)
	}

	parsedPort, err := strconv.ParseInt(nodeConfig.Port, 10, 32)
	if err != nil {
		return nil, err
	}

	port := uint32(parsedPort)

	switch c.NodeType {
	case "Shadowsocks":
		transportProtocol = "tcp"
	case "V2ray":
		transportProtocol = nodeConfig.Network
		tlsType := nodeConfig.Security
		if tlsType == "tls" || tlsType == "xtls" {
			enableTLS = true
		}
		if nodeConfig.EnableVless == "1" {
			enableVless = true
		}
	case "Trojan":
		enableTLS = true
		transportProtocol = "tcp"

		// Select transport protocol
		if nodeConfig.Network != "" {
			transportProtocol = nodeConfig.Network // try to read transport protocol from config
		}
	}

	// parse reality config
	realityConfig := new(api.REALITYConfig)
	if nodeConfig.RealityOpts != nil {
		r := nodeConfig.RealityOpts
		realityConfig = &api.REALITYConfig{
			Dest:             r.Dest,
			ProxyProtocolVer: r.ProxyProtocolVer,
			ServerNames:      r.ServerNames,
			PrivateKey:       r.PrivateKey,
			MinClientVer:     r.MinClientVer,
			MaxClientVer:     r.MaxClientVer,
			MaxTimeDiff:      r.MaxTimeDiff,
			ShortIds:         r.ShortIds,
		}
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              port,
		SpeedLimit:        speedLimit,
		AlterID:           alterID,
		TransportProtocol: transportProtocol,
		Host:              nodeConfig.Host,
		Path:              nodeConfig.Path,
		EnableTLS:         enableTLS,
		EnableVless:       enableVless,
		VlessFlow:         nodeConfig.Flow,
		CypherMethod:      nodeConfig.Method,
		ServerKey:         nodeConfig.ServerKey,
		ServiceName:       nodeConfig.Servicename,
		Header:            nodeConfig.Header,
		EnableREALITY:     nodeConfig.EnableReality,
		REALITYConfig:     realityConfig,
	}

	return nodeInfo, nil
}

// GetUserList will pull user
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	path := fmt.Sprintf("/api/node/%d/users/", c.NodeID)
	res, err := c.client.R().
		SetQueryParam("node_id", strconv.Itoa(c.NodeID)).
		SetHeader("If-None-Match", c.eTags["users"]).
		ForceContentType("application/json").
		Get(path)
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	userListResponse := new([]UserResponse)

	if err := json.Unmarshal(response, userListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(userListResponse), err)
	}

	userList, err := c.ParseUserListResponse(userListResponse)

	if err != nil {
		res, _ := json.Marshal(userListResponse)
		return nil, fmt.Errorf("parse user list failed: %s", string(res))
	}
	return userList, nil
}

// ParseUserListResponse parse the response for the given node info format
func (c *APIClient) ParseUserListResponse(userInfoResponse *[]UserResponse) (*[]api.UserInfo, error) {
	c.access.Lock()
	// Clear Last report log
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()

	var (
		deviceLimit      int    = 0
		localDeviceLimit int    = 0
		speedLimit       uint64 = 0
		userList         []api.UserInfo
	)

	for _, user := range *userInfoResponse {
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = user.DeviceLimit
		}

		// If there is still device available, add the user
		if deviceLimit > 0 && user.AliveIp > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[user.Id]; ok {
				lastOnline = v
			}
			// If there are any available device.
			if localDeviceLimit = deviceLimit - user.AliveIp + lastOnline; localDeviceLimit > 0 {
				deviceLimit = localDeviceLimit
				// If this backend server has reported any user in the last reporting period.
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
				// Remove this user.
			} else {
				continue
			}
		}

		if c.SpeedLimit > 0 {
			speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
		} else {
			speedLimit = uint64((user.SpeedLimit * 1000000) / 8)
		}

		userList = append(userList, api.UserInfo{
			UID:         user.Id,
			UUID:        user.Uuid,
			Passwd:      user.Passwd,
			SpeedLimit:  speedLimit,
			DeviceLimit: deviceLimit,
			Method:      user.Method,
		})
	}

	return &userList, nil
}

// ReportNodeStatus reports the node status
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	path := fmt.Sprintf("/api/node/%d/", c.NodeID)
	systemLoad := SystemLoad{
		Uptime: strconv.FormatUint(nodeStatus.Uptime, 10),
		Load:   fmt.Sprintf("%.2f %.2f %.2f", nodeStatus.CPU/100, nodeStatus.Mem/100, nodeStatus.Disk/100),
	}

	res, err := c.client.R().
		SetBody(systemLoad).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineUser, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = OnlineUser{Uid: user.UID, Ip: user.IP}
		// if _, ok := reportOnline[user.UID]; ok {
		// 	reportOnline[user.UID]++
		// } else {
		// 	reportOnline[user.UID] = 1
		// }
		reportOnline[user.UID]++ // will start from 1 if key doesn't exist
	}
	c.LastReportOnline = reportOnline // Update LastReportOnline

	path := fmt.Sprintf("/api/node/%d/users/aliveip/", c.NodeID)
	res, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			Uid:      traffic.UID,
			Email:    traffic.Email,
			Upload:   traffic.Upload,
			Download: traffic.Download}
	}

	path := fmt.Sprintf("/api/node/%d/users/traffic/", c.NodeID)
	res, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule will pull the audit rule
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	path := fmt.Sprintf("/api/node/%d/rules/", c.NodeID)
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["rules"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.RuleNotModified)
	}

	if res.Header().Get("ETag") != "" && res.Header().Get("ETag") != c.eTags["rules"] {
		c.eTags["rules"] = res.Header().Get("ETag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	ruleListResponse := new([]RuleItem)

	if err := json.Unmarshal(response, ruleListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(ruleListResponse), err)
	}

	for _, r := range *ruleListResponse {
		ruleList = append(ruleList, api.DetectRule{
			ID:      r.Id,
			Pattern: regexp.MustCompile(r.Pattern),
		})
	}
	return &ruleList, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {

	data := make([]IllegalItem, len(*detectResultList))
	for i, r := range *detectResultList {
		data[i] = IllegalItem{
			RuleID: r.RuleID,
			Uid:    r.UID,
		}
	}
	path := fmt.Sprintf("/api/node/%d/users/illegal/", c.NodeID)
	res, err := c.client.R().
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}
