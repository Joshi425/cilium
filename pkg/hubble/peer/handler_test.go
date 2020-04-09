// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package peer

import (
	"net"
	"sync"
	"testing"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"

	"github.com/stretchr/testify/assert"
)

func TestNodeAdd(t *testing.T) {
	tests := []struct {
		name string
		arg  node.Node
		want *peerpb.ChangeNotification
	}{
		{
			name: "node with just a name",
			arg: node.Node{
				Name: "name",
			},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name: "node with just a name and cluster",
			arg: node.Node{
				Name:    "name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name: "node with name, cluster and one internal IP address",
			arg: node.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []node.Address{
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name: "node with name, cluster and one external IP address",
			arg: node.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []node.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler()
			defer h.Close()

			var got *peerpb.ChangeNotification
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				got = <-h.C
				wg.Done()
			}()
			h.NodeAdd(tt.arg)
			wg.Wait()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNodeUpdate(t *testing.T) {
	type args struct {
		old, updated node.Node
	}
	tests := []struct {
		name string
		args args
		want *peerpb.ChangeNotification
	}{
		{
			name: "node with just a name",
			args: args{
				node.Node{}, node.Node{
					Name: "name",
				}},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
			},
		}, {
			name: "node with just a name and cluster",
			args: args{
				node.Node{}, node.Node{
					Name:    "name",
					Cluster: "cluster",
				}},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
			},
		}, {
			name: "node with name, cluster and one internal IP address",
			args: args{
				node.Node{}, node.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []node.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					}},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
			},
		}, {
			name: "node with name, cluster and one external IP address",
			args: args{
				node.Node{}, node.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []node.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					},
				}},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler()
			defer h.Close()

			var got *peerpb.ChangeNotification
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				got = <-h.C
				wg.Done()
			}()
			h.NodeUpdate(tt.args.old, tt.args.updated)
			wg.Wait()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNodeDelete(t *testing.T) {
	tests := []struct {
		name string
		arg  node.Node
		want *peerpb.ChangeNotification
	}{
		{
			name: "node with just a name",
			arg: node.Node{
				Name: "name",
			},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name: "node with just a name and cluster",
			arg: node.Node{
				Name:    "name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name: "node with name, cluster and one internal IP address",
			arg: node.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []node.Address{
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name: "node with name, cluster and one external IP address",
			arg: node.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []node.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler()
			defer h.Close()

			var got *peerpb.ChangeNotification
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				got = <-h.C
				wg.Done()
			}()
			h.NodeDelete(tt.arg)
			wg.Wait()
			assert.Equal(t, tt.want, got)
		})
	}
}
