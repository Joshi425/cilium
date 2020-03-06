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

package ipam

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/controller"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/trigger"

	. "gopkg.in/check.v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mustNewCIDR(cidr string) *net.IPNet {
	_, clusterCIDR, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return clusterCIDR
}

func mustNewTrigger(f func(), minInterval time.Duration) *trigger.Trigger {
	t, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: minInterval,
		TriggerFunc: func(reasons []string) {
			f()
		},
		Name: "",
	})
	if err != nil {
		panic(err)
	}
	return t
}

type mockCIDRAllocator struct {
	OnOccupy       func(cidr *net.IPNet) error
	OnAllocateNext func() (*net.IPNet, error)
	OnRelease      func(cidr *net.IPNet) error
	OnIsAllocated  func(cidr *net.IPNet) (bool, error)
}

func (d *mockCIDRAllocator) Occupy(cidr *net.IPNet) error {
	if d.OnOccupy != nil {
		return d.OnOccupy(cidr)
	}
	panic("d.Occupy should not be called!")
}

func (d *mockCIDRAllocator) AllocateNext() (*net.IPNet, error) {
	if d.OnAllocateNext != nil {
		return d.OnAllocateNext()
	}
	panic("d.AllocateNext should not be called!")
}

func (d *mockCIDRAllocator) Release(cidr *net.IPNet) error {
	if d.OnRelease != nil {
		return d.OnRelease(cidr)
	}
	panic("d.Release should not be called!")
}

func (d *mockCIDRAllocator) IsAllocated(cidr *net.IPNet) (bool, error) {
	if d.OnIsAllocated != nil {
		return d.OnIsAllocated(cidr)
	}
	panic("d.IsAllocated should not be called!")
}

type k8sNodeMock struct {
	OnUpdate       func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error)
	OnUpdateStatus func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error)
	OnGet          func(node string) (*v2.CiliumNode, error)
	OnCreate       func(n *v2.CiliumNode) (*v2.CiliumNode, error)
	OnDelete       func(nodeName string) error
}

func (k *k8sNodeMock) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnUpdate != nil {
		return k.OnUpdate(origNode, node)
	}
	panic("d.Update should not be called!")
}

func (k *k8sNodeMock) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnUpdateStatus != nil {
		return k.OnUpdateStatus(origNode, node)
	}
	panic("d.UpdateStatus should not be called!")
}

func (k *k8sNodeMock) Get(node string) (*v2.CiliumNode, error) {
	if k.OnGet != nil {
		return k.OnGet(node)
	}
	panic("d.Get should not be called!")
}

func (k *k8sNodeMock) Create(n *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnCreate != nil {
		return k.OnCreate(n)
	}
	panic("d.Create should not be called!")
}

func (k *k8sNodeMock) Delete(nodeName string) error {
	if k.OnDelete != nil {
		return k.OnDelete(nodeName)
	}
	panic("d.Delete should not be called!")
}

func (s *IPAMSuite) TestNodesPodCIDRManager_Create(c *C) {
	var reSyncCalls int
	type fields struct {
		k8sReSyncController *controller.Manager
		k8sReSync           *trigger.Trigger
		v4ClusterCIDR       *mockCIDRAllocator
		v6ClusterCIDR       *mockCIDRAllocator
		nodes               map[string]*nodeCIDRs
		ciliumNodesToK8s    map[string]*ciliumNodeK8sOp
	}
	type args struct {
		node *v2.CiliumNode
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
		want        bool
	}{
		{
			name: "test-1 - should allocate a v4 addr",
			want: true,
			testSetup: func() *fields {
				reSyncCalls = 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							return mustNewCIDR("10.10.0.0/24"), nil
						},
					},
					nodes:            map[string]*nodeCIDRs{},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls++
						return
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				time.Sleep(2 * time.Millisecond)
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
					},
				})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				})
				c.Assert(reSyncCalls, checker.Equals, 1)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
		{
			name: "test-2 - failed to allocate a v4 addr",
			want: false,
			testSetup: func() *fields {
				reSyncCalls = 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							return nil, fmt.Errorf("Allocator full!")
						},
					},
					nodes:            map[string]*nodeCIDRs{},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls++
						return
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				time.Sleep(2 * time.Millisecond)
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Status: v2.NodeStatus{
								IPAM: ipamTypes.IPAMStatus{
									OperatorStatus: ipamTypes.OperatorStatus{
										Error: "Allocator full!",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				})
				c.Assert(reSyncCalls, checker.Equals, 1)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
		{
			name: "test-3 - node is already allocated with the requested pod CIDRs",
			want: true,
			testSetup: func() *fields {
				return &fields{
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: []string{
								"10.10.0.0/24",
							},
						},
					},
				},
			},
		},
		{
			name: "test-4 - node is requesting pod CIDRs, it's already locally allocated but the spec is not updated",
			want: true,
			testSetup: func() *fields {
				reSyncCalls = 0
				return &fields{
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						},
					},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls++
						return
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				time.Sleep(2 * time.Millisecond)
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
					},
				})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				})
				c.Assert(reSyncCalls, checker.Equals, 1)
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			k8sReSyncController: tt.fields.k8sReSyncController,
			k8sReSync:           tt.fields.k8sReSync,
			v4ClusterCIDR:       tt.fields.v4ClusterCIDR,
			v6ClusterCIDR:       tt.fields.v6ClusterCIDR,
			nodes:               tt.fields.nodes,
			ciliumNodesToK8s:    tt.fields.ciliumNodesToK8s,
		}
		got := n.Create(tt.args.node)
		c.Assert(got, checker.Equals, tt.want, Commentf("Test Name: %s", tt.name))

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) TestNodesPodCIDRManager_Delete(c *C) {
	var reSyncCalls int
	type fields struct {
		k8sReSyncController *controller.Manager
		k8sReSync           *trigger.Trigger
		v4ClusterCIDR       *mockCIDRAllocator
		v6ClusterCIDR       *mockCIDRAllocator
		nodes               map[string]*nodeCIDRs
		ciliumNodesToK8s    map[string]*ciliumNodeK8sOp
	}
	type args struct {
		nodeName string
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
	}{
		{
			name: "test-1 - should release the v4 CIDR",
			testSetup: func() *fields {
				reSyncCalls = 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnRelease: func(cidr *net.IPNet) error {
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return nil
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						},
					},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls++
						return
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				time.Sleep(2 * time.Millisecond)
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				})
				c.Assert(reSyncCalls, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
			},
		},
		{
			name: "test-2 - should be a no op since the node is not allocated",
			testSetup: func() *fields {
				reSyncCalls = 0
				return &fields{
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{})
				c.Assert(reSyncCalls, checker.Equals, 0)
			},
			args: args{
				nodeName: "node-1",
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			k8sReSyncController: tt.fields.k8sReSyncController,
			k8sReSync:           tt.fields.k8sReSync,
			v4ClusterCIDR:       tt.fields.v4ClusterCIDR,
			v6ClusterCIDR:       tt.fields.v6ClusterCIDR,
			nodes:               tt.fields.nodes,
			ciliumNodesToK8s:    tt.fields.ciliumNodesToK8s,
		}
		n.Delete(tt.args.nodeName)

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) TestNodesPodCIDRManager_Resync(c *C) {
	var reSyncCalls int
	type fields struct {
		k8sReSync *trigger.Trigger
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
	}{
		{
			name: "test-1",
			testSetup: func() *fields {
				return &fields{
					k8sReSync: mustNewTrigger(func() {
						reSyncCalls++
						return
					}, time.Millisecond),
				}
			},
			testPostRun: func(fields *fields) {
				time.Sleep(2 * time.Millisecond)
				c.Assert(reSyncCalls, checker.Equals, 1)
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			k8sReSync: tt.fields.k8sReSync,
		}
		n.Resync(context.Background(), time.Time{})

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) TestNodesPodCIDRManager_Update(c *C) {
	type fields struct {
		k8sReSyncController *controller.Manager
		k8sReSync           *trigger.Trigger
		v4ClusterCIDR       *mockCIDRAllocator
		v6ClusterCIDR       *mockCIDRAllocator
		nodes               map[string]*nodeCIDRs
		ciliumNodesToK8s    map[string]*ciliumNodeK8sOp
	}
	type args struct {
		node *v2.CiliumNode
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
		want        bool
	}{
		{
			name: "test-1 - should allocate a v4 addr",
			want: true,
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							return mustNewCIDR("10.10.0.0/24"), nil
						},
					},
					nodes:            map[string]*nodeCIDRs{},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						return
					}, time.Second),
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
					},
				})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
		{
			name: "test-2 - failed to allocate a v4 addr",
			want: false,
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							return nil, fmt.Errorf("Allocator full!")
						},
					},
					nodes:            map[string]*nodeCIDRs{},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						return
					}, time.Second),
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Status: v2.NodeStatus{
								IPAM: ipamTypes.IPAMStatus{
									OperatorStatus: ipamTypes.OperatorStatus{
										Error: "Allocator full!",
									},
								},
							},
						},
						op: k8sOpUpdateStatus,
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
		{
			name: "test-3 - node is already allocated with the requested pod CIDRs",
			want: true,
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							return nil, fmt.Errorf("Allocator full!")
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v2.NodeSpec{
						IPAM: ipamTypes.IPAMSpec{
							PodCIDRs: []string{
								"10.10.0.0/24",
							},
						},
					},
				},
			},
		},
		{
			name: "test-4 - node is requesting pod CIDRs, it's already allocated locally but the spec is not updated",
			want: true,
			testSetup: func() *fields {
				return &fields{
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						},
					},
					ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{},
					k8sReSync: mustNewTrigger(func() {
						return
					}, time.Second),
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
					},
				})
				c.Assert(fields.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					},
				})
			},
			args: args{
				node: &v2.CiliumNode{
					ObjectMeta: v1.ObjectMeta{
						Name: "node-1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			k8sReSyncController: tt.fields.k8sReSyncController,
			k8sReSync:           tt.fields.k8sReSync,
			v4ClusterCIDR:       tt.fields.v4ClusterCIDR,
			v6ClusterCIDR:       tt.fields.v6ClusterCIDR,
			nodes:               tt.fields.nodes,
			ciliumNodesToK8s:    tt.fields.ciliumNodesToK8s,
		}
		got := n.Update(tt.args.node)
		c.Assert(got, checker.Equals, tt.want, Commentf("Test Name: %s", tt.name))

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) TestNodesPodCIDRManager_allocateIPNets(c *C) {
	var (
		onOccupyCallsv4, releaseCallsv4, onIsAllocatedCallsv4 int
		onOccupyCallsv6, releaseCallsv6, onIsAllocatedCallsv6 int
	)

	type fields struct {
		v4ClusterCIDR *mockCIDRAllocator
		v6ClusterCIDR *mockCIDRAllocator
		nodes         map[string]*nodeCIDRs
	}
	type args struct {
		nodeName string
		v4CIDR   *net.IPNet
		v6CIDR   *net.IPNet
	}
	tests := []struct {
		name          string
		testSetup     func() *fields
		testPostRun   func(fields *fields)
		fields        *fields
		args          args
		wantAllocated bool
		wantErr       bool
	}{
		{
			name: "test-1 - should not allocate anything because the node had previously allocated CIDRs",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{},
					v6ClusterCIDR: &mockCIDRAllocator{},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
							v6PodCIDR: mustNewCIDR("fd00::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						v6PodCIDR: mustNewCIDR("fd00::/80"),
					},
				})
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDR("10.10.0.0/24"),
				v6CIDR:   mustNewCIDR("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       false,
		},
		{
			name: "test-2 - should allocate both CIDRs",
			testSetup: func() *fields {
				releaseCallsv4, releaseCallsv6 = 0, 0
				onOccupyCallsv4, onOccupyCallsv6 = 0, 0
				onIsAllocatedCallsv4, onIsAllocatedCallsv6 = 0, 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnOccupy: func(cidr *net.IPNet) error {
							onOccupyCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return nil
						},
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							onIsAllocatedCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return false, nil
						},
					},
					v6ClusterCIDR: &mockCIDRAllocator{
						OnOccupy: func(cidr *net.IPNet) error {
							onOccupyCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							return nil
						},
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							onIsAllocatedCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							return false, nil
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						v6PodCIDR: mustNewCIDR("fd00::/80"),
					},
				})
				c.Assert(onIsAllocatedCallsv4, checker.Equals, 1)
				c.Assert(onOccupyCallsv4, checker.Equals, 1)
				c.Assert(releaseCallsv4, checker.Equals, 0)

				c.Assert(onIsAllocatedCallsv6, checker.Equals, 1)
				c.Assert(onOccupyCallsv6, checker.Equals, 1)
				c.Assert(releaseCallsv6, checker.Equals, 0)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDR("10.10.0.0/24"),
				v6CIDR:   mustNewCIDR("fd00::/80"),
			},
			wantAllocated: true,
			wantErr:       false,
		},
		{
			name: "test-3 - the v6 allocator is full!",
			testSetup: func() *fields {
				releaseCallsv4, releaseCallsv6 = 0, 0
				onOccupyCallsv4, onOccupyCallsv6 = 0, 0
				onIsAllocatedCallsv4, onIsAllocatedCallsv6 = 0, 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							onIsAllocatedCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return false, nil
						},
						OnOccupy: func(cidr *net.IPNet) error {
							onOccupyCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return nil
						},
						OnRelease: func(cidr *net.IPNet) error {
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							releaseCallsv4++
							return nil
						},
					},
					v6ClusterCIDR: &mockCIDRAllocator{
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							onIsAllocatedCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							return false, nil
						},
						OnOccupy: func(cidr *net.IPNet) error {
							onOccupyCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							// In reality this would never happen because
							// if we have checked the CIDR was free.
							// However, the allocator can return a random error regardless.
							return fmt.Errorf("Allocator full!")
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{})
				c.Assert(onIsAllocatedCallsv4, checker.Equals, 1)
				c.Assert(onOccupyCallsv4, checker.Equals, 1)
				c.Assert(releaseCallsv4, checker.Equals, 1)

				c.Assert(onIsAllocatedCallsv6, checker.Equals, 1)
				c.Assert(onOccupyCallsv6, checker.Equals, 1)
				c.Assert(releaseCallsv6, checker.Equals, 0)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDR("10.10.0.0/24"),
				v6CIDR:   mustNewCIDR("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       true,
		},
		{
			name: "test-4 - should release the old CIDRs previously allocated by the same node and allocate the requested CIDRs",
			testSetup: func() *fields {
				releaseCallsv4, releaseCallsv6 = 0, 0
				onOccupyCallsv4, onOccupyCallsv6 = 0, 0
				onIsAllocatedCallsv4, onIsAllocatedCallsv6 = 0, 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							onIsAllocatedCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return false, nil
						},
						OnOccupy: func(cidr *net.IPNet) error {
							onOccupyCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							return nil
						},
						OnRelease: func(cidr *net.IPNet) error {
							releaseCallsv4++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.1.0/24"))
							return nil
						},
					},
					v6ClusterCIDR: &mockCIDRAllocator{
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							onIsAllocatedCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							return false, nil
						},
						OnOccupy: func(cidr *net.IPNet) error {
							onOccupyCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							return nil
						},
						OnRelease: func(cidr *net.IPNet) error {
							releaseCallsv6++
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd01::/80"))
							return nil
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.1.0/24"),
							v6PodCIDR: mustNewCIDR("fd01::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						v6PodCIDR: mustNewCIDR("fd00::/80"),
					},
				})
				c.Assert(onOccupyCallsv4, checker.Equals, 1)
				c.Assert(releaseCallsv4, checker.Equals, 1)
				c.Assert(onOccupyCallsv6, checker.Equals, 1)
				c.Assert(releaseCallsv6, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDR("10.10.0.0/24"),
				v6CIDR:   mustNewCIDR("fd00::/80"),
			},
			wantAllocated: true,
			wantErr:       false,
		},
		{
			name: "test-5 - should release the old CIDRs previously allocated by the same node " +
				"and allocate the requested CIDRs but the v6 allocator is full!",
			testSetup: func() *fields {
				releaseCallsv4, releaseCallsv6 = 0, 0
				onOccupyCallsv4, onOccupyCallsv6 = 0, 0
				onIsAllocatedCallsv4, onIsAllocatedCallsv6 = 0, 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
						// First we will allocate the new CIDR
						c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
						onIsAllocatedCallsv4++
						return false, nil
					},
						OnOccupy: func(cidr *net.IPNet) error {
							if onOccupyCallsv4 == 0 {
								// First we will allocate the old CIDR
								c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							} else {
								// And since the v6 allocator returned an error, we will allocated the previously allocated
								c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.1.0/24"))
							}
							onOccupyCallsv4++
							return nil
						},
						OnRelease: func(cidr *net.IPNet) error {
							if releaseCallsv4 == 0 {
								// First we will release the old CIDR
								c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.1.0/24"))
							} else {
								// And since the v6 allocator returned an error, we will release the previously allocated
								c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							}
							releaseCallsv4++
							return nil
						},
					},
					v6ClusterCIDR: &mockCIDRAllocator{
						OnIsAllocated: func(cidr *net.IPNet) (bool, error) {
							// First we will allocate the new CIDR
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
							onIsAllocatedCallsv6++
							return false, nil
						},
						OnOccupy: func(cidr *net.IPNet) error {
							if onOccupyCallsv6 == 0 {
								// First we will allocate the new CIDR
								c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
								onOccupyCallsv6++
								return fmt.Errorf("Allocator full!")
							} else {
								// And since the v6 allocator returned an error, we will allocated the previously allocated
								c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd01::/80"))
							}
							onOccupyCallsv6++
							return nil
						},
						OnRelease: func(cidr *net.IPNet) error {
							// We will release the old CIDR
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd01::/80"))
							releaseCallsv6++
							return nil
						},
					},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.1.0/24"),
							v6PodCIDR: mustNewCIDR("fd01::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.1.0/24"),
						v6PodCIDR: mustNewCIDR("fd01::/80"),
					},
				})
				c.Assert(onOccupyCallsv4, checker.Equals, 2)
				c.Assert(releaseCallsv4, checker.Equals, 2)
				c.Assert(onOccupyCallsv6, checker.Equals, 2)
				c.Assert(releaseCallsv6, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDR("10.10.0.0/24"),
				v6CIDR:   mustNewCIDR("fd00::/80"),
			},
			wantAllocated: false,
			wantErr:       true,
		},
		{
			name: "test-6 - should not allocate anything because there isn't" +
				" an allocator available for the CIDR family requested!",
			testSetup: func() *fields {
				return &fields{
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.1.0/24"),
							v6PodCIDR: mustNewCIDR("fd01::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.1.0/24"),
						v6PodCIDR: mustNewCIDR("fd01::/80"),
					},
				})
			},
			args: args{
				nodeName: "node-1",
				v4CIDR:   mustNewCIDR("10.10.0.0/24"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			v4ClusterCIDR: tt.fields.v4ClusterCIDR,
			v6ClusterCIDR: tt.fields.v6ClusterCIDR,
			nodes:         tt.fields.nodes,
		}
		gotAllocated, err := n.allocateIPNets(tt.args.nodeName, tt.args.v4CIDR, tt.args.v6CIDR)
		gotErr := err != nil
		c.Assert(gotErr, checker.Equals, tt.wantErr, Commentf("Test Name: %s", tt.name))
		c.Assert(gotAllocated, checker.Equals, tt.wantAllocated, Commentf("Test Name: %s", tt.name))

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) TestNodesPodCIDRManager_allocateNext(c *C) {
	var (
		allocateNextCallsv4, releaseCallsv4 int
		allocateNextCallsv6                 int
	)

	type fields struct {
		v4ClusterCIDR *mockCIDRAllocator
		v6ClusterCIDR *mockCIDRAllocator
		nodes         map[string]*nodeCIDRs
	}
	type args struct {
		nodeName string
	}
	tests := []struct {
		testSetup     func() *fields
		testPostRun   func(fields *fields)
		name          string
		fields        *fields
		args          args
		wantV4CIDR    *net.IPNet
		wantV6CIDR    *net.IPNet
		wantAllocated bool
		wantErr       bool
	}{
		{
			name: "test-1 - should not allocate anything because the node had previously allocated CIDRs",
			testSetup: func() *fields {
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{},
					v6ClusterCIDR: &mockCIDRAllocator{},
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
							v6PodCIDR: mustNewCIDR("fd00::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						v6PodCIDR: mustNewCIDR("fd00::/80"),
					},
				})
			},
			args: args{
				nodeName: "node-1",
			},
			wantV4CIDR:    mustNewCIDR("10.10.0.0/24"),
			wantV6CIDR:    mustNewCIDR("fd00::/80"),
			wantAllocated: false,
			wantErr:       false,
		},
		{
			name: "test-2 - should allocate both CIDRs",
			testSetup: func() *fields {
				allocateNextCallsv4, allocateNextCallsv6 = 0, 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							allocateNextCallsv4++
							return mustNewCIDR("10.10.0.0/24"), nil
						},
					},
					v6ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							allocateNextCallsv6++
							return mustNewCIDR("fd00::/80"), nil
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{
					"node-1": {
						v4PodCIDR: mustNewCIDR("10.10.0.0/24"),
						v6PodCIDR: mustNewCIDR("fd00::/80"),
					},
				})
				c.Assert(allocateNextCallsv4, checker.Equals, 1)
				c.Assert(allocateNextCallsv6, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
			},
			wantV4CIDR:    mustNewCIDR("10.10.0.0/24"),
			wantV6CIDR:    mustNewCIDR("fd00::/80"),
			wantAllocated: true,
			wantErr:       false,
		},
		{
			name: "test-3 - the v6 allocator is full!",
			testSetup: func() *fields {
				allocateNextCallsv4, allocateNextCallsv6 = 0, 0
				releaseCallsv4 = 0
				return &fields{
					v4ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							allocateNextCallsv4++
							return mustNewCIDR("10.10.0.0/24"), nil
						},
						OnRelease: func(cidr *net.IPNet) error {
							c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.10.0.0/24"))
							releaseCallsv4++
							return nil
						},
					},
					v6ClusterCIDR: &mockCIDRAllocator{
						OnAllocateNext: func() (ipNet *net.IPNet, err error) {
							allocateNextCallsv6++
							return nil, fmt.Errorf("Allocator full!")
						},
					},
					nodes: map[string]*nodeCIDRs{},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(fields.nodes, checker.DeepEquals, map[string]*nodeCIDRs{})
				c.Assert(allocateNextCallsv4, checker.Equals, 1)
				c.Assert(allocateNextCallsv6, checker.Equals, 1)
				c.Assert(releaseCallsv4, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
			},
			wantAllocated: false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			v4ClusterCIDR: tt.fields.v4ClusterCIDR,
			v6ClusterCIDR: tt.fields.v6ClusterCIDR,
			nodes:         tt.fields.nodes,
		}
		gotV4CIDR, gotV6CIDR, gotAllocated, err := n.allocateNext(tt.args.nodeName)
		gotErr := err != nil
		c.Assert(gotErr, checker.Equals, tt.wantErr, Commentf("Test Name: %s", tt.name))
		c.Assert(gotV4CIDR, checker.DeepEquals, tt.wantV4CIDR, Commentf("Test Name: %s", tt.name))
		c.Assert(gotV6CIDR, checker.DeepEquals, tt.wantV6CIDR, Commentf("Test Name: %s", tt.name))
		c.Assert(gotAllocated, checker.Equals, tt.wantAllocated, Commentf("Test Name: %s", tt.name))

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) TestNodesPodCIDRManager_releaseIPNets(c *C) {
	var onReleaseCalls int

	type fields struct {
		v4ClusterCIDR *mockCIDRAllocator
		v6ClusterCIDR *mockCIDRAllocator
		nodes         map[string]*nodeCIDRs
	}
	type args struct {
		nodeName string
	}
	tests := []struct {
		testSetup   func() *fields
		testPostRun func(fields *fields)
		name        string
		fields      *fields
		args        args
		want        bool
	}{
		{
			name: "test-1",
			testSetup: func() *fields {
				return &fields{
					nodes: map[string]*nodeCIDRs{},
				}
			},
			args: args{
				nodeName: "node-1",
			},
			want: false,
		},
		{
			name: "test-2",
			testSetup: func() *fields {
				onReleaseCalls = 0
				cidrSet := &mockCIDRAllocator{
					OnRelease: func(cidr *net.IPNet) error {
						onReleaseCalls++
						c.Assert(cidr, checker.DeepEquals, mustNewCIDR("10.0.0.0/16"))
						return nil
					},
				}
				return &fields{
					v4ClusterCIDR: cidrSet,
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v4PodCIDR: mustNewCIDR("10.0.0.0/16"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(len(fields.nodes), checker.Equals, 0)
				c.Assert(onReleaseCalls, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
			},
			want: true,
		},
		{
			name: "test-3",
			testSetup: func() *fields {
				onReleaseCalls = 0
				cidrSet := &mockCIDRAllocator{
					OnRelease: func(cidr *net.IPNet) error {
						onReleaseCalls++
						c.Assert(cidr, checker.DeepEquals, mustNewCIDR("fd00::/80"))
						return nil
					},
				}
				return &fields{
					v6ClusterCIDR: cidrSet,
					nodes: map[string]*nodeCIDRs{
						"node-1": {
							v6PodCIDR: mustNewCIDR("fd00::/80"),
						},
					},
				}
			},
			testPostRun: func(fields *fields) {
				c.Assert(len(fields.nodes), checker.Equals, 0)
				c.Assert(onReleaseCalls, checker.Equals, 1)
			},
			args: args{
				nodeName: "node-1",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		tt.fields = tt.testSetup()
		n := &NodesPodCIDRManager{
			v4ClusterCIDR: tt.fields.v4ClusterCIDR,
			v6ClusterCIDR: tt.fields.v6ClusterCIDR,
			nodes:         tt.fields.nodes,
		}
		got := n.releaseIPNets(tt.args.nodeName)
		c.Assert(got, checker.Equals, tt.want, Commentf("Test Name: %s", tt.name))

		if tt.testPostRun != nil {
			tt.testPostRun(tt.fields)
		}
	}
}

func (s *IPAMSuite) Test_parsePodCIDRs(c *C) {
	type args struct {
		podCIDRs []string
	}
	tests := []struct {
		name    string
		args    args
		want    *net.IPNet
		want1   *net.IPNet
		wantErr bool
	}{
		{
			name: "test-1",
			args: args{
				podCIDRs: []string{
					"1.1.1.1/20",
					"1.1.1.1/28",
				},
			},
			wantErr: true,
		},
		{
			name: "test-2",
			args: args{
				podCIDRs: []string{
					"fd00::1/64",
					"fd01::/64",
				},
			},
			wantErr: true,
		},
		{
			name: "test-3",
			args: args{
				podCIDRs: []string{
					"fd00::1/64",
					"1.1.1.1/28",
				},
			},
			want: &net.IPNet{
				IP:   net.ParseIP("1.1.1.0").To4(),
				Mask: net.CIDRMask(28, 32),
			},
			want1: &net.IPNet{
				IP:   net.ParseIP("fd00::"),
				Mask: net.CIDRMask(64, 128),
			},
			wantErr: false,
		},
		{
			name: "test-4",
			args: args{
				podCIDRs: []string{
					"fd00::1/64",
				},
			},
			want1: &net.IPNet{
				IP:   net.ParseIP("fd00::"),
				Mask: net.CIDRMask(64, 128),
			},
			wantErr: false,
		},
		{
			name: "test-5",
			args: args{
				podCIDRs: []string{
					"1.1.1.1/28",
				},
			},
			want: &net.IPNet{
				IP:   net.ParseIP("1.1.1.0").To4(),
				Mask: net.CIDRMask(28, 32),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		got, got1, err := parsePodCIDRs(tt.args.podCIDRs)
		gotErr := err != nil
		c.Assert(gotErr, checker.Equals, tt.wantErr, Commentf("Test Name: %s", tt.name))
		c.Assert(got, checker.DeepEquals, tt.want, Commentf("Test Name: %s", tt.name))
		c.Assert(got1, checker.DeepEquals, tt.want1, Commentf("Test Name: %s", tt.name))
	}
}

func (s *IPAMSuite) Test_syncToK8s(c *C) {
	const k8sOpGet = k8sOp(99)

	calls := map[k8sOp]int{}
	type args struct {
		nodeGetter       *k8sNodeMock
		ciliumNodesToK8s map[string]*ciliumNodeK8sOp
	}
	tests := []struct {
		testSetup   func()
		testPostRun func(args *args)
		name        string
		args        *args
		wantErr     bool
	}{
		{
			name: "test-1 - create a Cilium Node",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnCreate: func(n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpCreate]++
						c.Assert(n, checker.DeepEquals, &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						})
						return nil, nil
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpCreate: 1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{})
			},
			wantErr: false,
		},
		{
			name: "test-2 - create a Cilium Node but it already exists so the next operation should be an update",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnCreate: func(n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpCreate]++
						c.Assert(n, checker.DeepEquals, &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						})
						return nil, &k8sErrors.StatusError{
							ErrStatus: v1.Status{
								Reason: v1.StatusReasonAlreadyExists,
							}}
					},
					OnGet: func(nodeName string) (node *v2.CiliumNode, err error) {
						calls[k8sOpGet]++
						c.Assert(nodeName, checker.Equals, "node-1")
						return &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						}, nil
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpCreate: 1,
					k8sOpGet:    1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					}})
			},
			wantErr: true,
		},
		{
			name: "test-3 - create a Cilium Node but it already exists. When performing a get" +
				" the node was removed upstream." +
				" The operator is listening for node events, if the node is removed," +
				" a delete event will eventually remove the node from the list of nodes that" +
				" need to be synchronized with k8s",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnCreate: func(n *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpCreate]++
						c.Assert(n, checker.DeepEquals, &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						})
						return nil, &k8sErrors.StatusError{
							ErrStatus: v1.Status{
								Reason: v1.StatusReasonAlreadyExists,
							}}
					},
					OnGet: func(nodeName string) (node *v2.CiliumNode, err error) {
						calls[k8sOpGet]++
						c.Assert(nodeName, checker.Equals, "node-1")
						return nil, &k8sErrors.StatusError{
							ErrStatus: v1.Status{
								Reason: v1.StatusReasonNotFound,
							}}
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpCreate: 1,
					k8sOpGet:    1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpCreate,
					},
				})
			},
			wantErr: true,
		},
		{
			name: "test-4 - try to update a node that no longer exists. We should stop" +
				" trying to update it again.",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnUpdate: func(n, _ *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpUpdate]++
						c.Assert(n, checker.DeepEquals, &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						})
						return nil, &k8sErrors.StatusError{
							ErrStatus: v1.Status{
								Reason: v1.StatusReasonNotFound,
							}}
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdate,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpUpdate: 1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{})
			},
			wantErr: false,
		},
		{
			name: "test-5 - try update the status only",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnUpdateStatus: func(n, _ *v2.CiliumNode) (node *v2.CiliumNode, err error) {
						calls[k8sOpUpdateStatus]++
						c.Assert(n, checker.DeepEquals, &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						})
						return nil, nil
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						ciliumNode: &v2.CiliumNode{
							ObjectMeta: v1.ObjectMeta{
								Name: "node-1",
							},
							Spec: v2.NodeSpec{
								IPAM: ipamTypes.IPAMSpec{
									PodCIDRs: []string{
										"10.10.0.0/24",
									},
								},
							},
						},
						op: k8sOpUpdateStatus,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpUpdateStatus: 1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{})
			},
			wantErr: false,
		},
		{
			name: "test-6 - delete node and ignore error if node was not found",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnDelete: func(nodeName string) error {
						calls[k8sOpDelete]++
						c.Assert(nodeName, checker.DeepEquals, "node-1")
						return &k8sErrors.StatusError{
							ErrStatus: v1.Status{
								Reason: v1.StatusReasonNotFound,
							}}
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpDelete: 1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{})
			},
			wantErr: false,
		},
		{
			name: "test-7 - delete node and do not ignore error if node was not found",
			testSetup: func() {
				calls = map[k8sOp]int{}
			},
			args: &args{
				nodeGetter: &k8sNodeMock{
					OnDelete: func(nodeName string) error {
						calls[k8sOpDelete]++
						c.Assert(nodeName, checker.DeepEquals, "node-1")
						return &k8sErrors.StatusError{
							ErrStatus: v1.Status{
								Reason: v1.StatusReasonBadRequest,
							}}
					},
				},
				ciliumNodesToK8s: map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				},
			},
			testPostRun: func(args *args) {
				c.Assert(calls, checker.DeepEquals, map[k8sOp]int{
					k8sOpDelete: 1,
				})
				c.Assert(args.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{
					"node-1": {
						op: k8sOpDelete,
					},
				})
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt.testSetup()
		gotErr := syncToK8s(tt.args.nodeGetter, tt.args.ciliumNodesToK8s) != nil
		c.Assert(gotErr, checker.Equals, tt.wantErr, Commentf("Test Name: %s", tt.name))
		if tt.testPostRun != nil {
			tt.testPostRun(tt.args)
		}
	}
}

func (s *IPAMSuite) TestNewNodesPodCIDRManager(c *C) {
	onDeleteCalls := 0
	deleted2Times := make(chan struct{})
	nodeGetter := &k8sNodeMock{
		OnDelete: func(nodeName string) error {
			onDeleteCalls++
			switch {
			case onDeleteCalls < 2:
				return &k8sErrors.StatusError{
					ErrStatus: v1.Status{
						Reason: v1.StatusReasonBadRequest,
					}}
			case onDeleteCalls == 2:
				close(deleted2Times)
				fallthrough
			default:
				return nil
			}
		},
	}
	updateK8sInterval = time.Second
	nm := NewNodesPodCIDRManager(nil, nil, nodeGetter, nil)

	nm.k8sReSync.Trigger()
	// Waiting 2 times the amount of time set in the trigger
	time.Sleep(2 * time.Second)
	c.Assert(onDeleteCalls, checker.Equals, 0)

	nm.Mutex.Lock()
	nm.ciliumNodesToK8s = map[string]*ciliumNodeK8sOp{
		"node-1": {
			op: k8sOpDelete,
		},
	}
	nm.Mutex.Unlock()
	select {
	case <-deleted2Times:
	case <-time.Tick(5 * time.Second):
		c.Error("The controller should have tried to delete the node by now")
	}
	c.Assert(nm.ciliumNodesToK8s, checker.DeepEquals, map[string]*ciliumNodeK8sOp{})
	// Wait for the controller to try more times, the number of deletedCalls
	// should not be different because we have successfully deleted the node.
	time.Sleep(2 * time.Second)
	c.Assert(onDeleteCalls, checker.Equals, 2)
}
