package nextpanel_test

import (
	"fmt"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/nextpanel"
)

const (
	KEY string = "(hpyrS]]x]#Q+zy+"
)

func CreateClient(nodeId int, nodeType string) api.API {
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:3000",
		Key:      KEY,
		NodeID:   nodeId,
		NodeType: nodeType,
	}
	client := nextpanel.New(apiConfig)
	return client
}

func TestGetV2rayNodeInfo(t *testing.T) {
	client := CreateClient(1, "V2ray")

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetShadowsocksNodeInfo(t *testing.T) {
	client := CreateClient(2, "Shadowsocks")

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeInfo(t *testing.T) {
	client := CreateClient(3, "Trojan")

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	client := CreateClient(1, "V2RAY")

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	t.Log(userList)
}

func TestReportNodeStatus(t *testing.T) {
	client := CreateClient(1, "V2RAY")
	nodeStatus := &api.NodeStatus{
		CPU: 1, Mem: 1, Disk: 1, Uptime: 256,
	}
	err := client.ReportNodeStatus(nodeStatus)
	if err != nil {
		t.Error(err)
	}
}

func TestReportReportNodeOnlineUsers(t *testing.T) {
	client := CreateClient(1, "V2RAY")
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	onlineUserList := make([]api.OnlineUser, len(*userList))
	for i, userInfo := range *userList {
		onlineUserList[i] = api.OnlineUser{
			UID: userInfo.UID,
			IP:  fmt.Sprintf("1.1.1.%d", i+1),
		}
	}
	// client.Debug()
	err = client.ReportNodeOnlineUsers(&onlineUserList)
	if err != nil {
		t.Error(err)
	}
}

func TestReportReportUserTraffic(t *testing.T) {
	client := CreateClient(1, "V2RAY")
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Email:    "admin@example.com",
			Upload:   114515,
			Download: 114514,
		}
	}

	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	client := CreateClient(1, "V2RAY")

	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}

func TestReportIllegal(t *testing.T) {
	client := CreateClient(1, "V2RAY")

	detectResult := []api.DetectResult{
		{UID: 1, RuleID: 1},
	}
	client.Debug()
	err := client.ReportIllegal(&detectResult)
	if err != nil {
		t.Error(err)
	}
}
