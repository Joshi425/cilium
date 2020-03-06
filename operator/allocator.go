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

package main

import (
	"fmt"
	"net"

	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/cilium/ipam/cidrset"
)

// startAzureAllocator starts the Azure IP allocator
func startOperatorAllocator() error {
	log.Info("Starting Operator IP allocator...")

	var ipamTriggerMetrics trigger.MetricsObserver
	if option.Config.EnableMetrics {
		// triggerMetrics := ipamMetrics.NewTriggerMetrics(metricNamespace, "k8s_sync")
		// triggerMetrics.Register(registry)
		// ipamTriggerMetrics = triggerMetrics
	} else {
		ipamTriggerMetrics = &ipamMetrics.NoOpMetricsObserver{}
	}

	var v4CIDRSet, v6CIDRSet *cidrset.CidrSet
	if len(option.Config.IPAMOperatorV4CIDR) != 0 {
		v4Addr, v4CIDR, err := net.ParseCIDR(option.Config.IPAMOperatorV4CIDR)
		if err != nil {
			return err
		}
		if !ipPkg.IsIPv4(v4Addr) {
			return fmt.Errorf("IPv4CIDR is not v4 family: %s", v4Addr)
		}
		if !option.Config.EnableIPv4 {
			return fmt.Errorf("IPv4CIDR can not be set if IPv4 is not enabled")
		}
		v4CIDRSet, err = cidrset.NewCIDRSet(v4CIDR, option.Config.NodeCIDRMaskSizeIPv4)
		if err != nil {
			return fmt.Errorf("unable to create IPv4 pod CIDR: %s", err)
		}

	}
	if len(option.Config.IPAMOperatorV6CIDR) != 0 {
		v6Addr, v6CIDR, err := net.ParseCIDR(option.Config.IPAMOperatorV6CIDR)
		if err != nil {
			return err
		}
		if ipPkg.IsIPv4(v6Addr) {
			return fmt.Errorf("IPv6CIDR is not v6 family: %s", v6Addr)
		}
		if !option.Config.EnableIPv6 {
			return fmt.Errorf("IPv4CIDR can not be set if IPv4 is not enabled")
		}
		v6CIDRSet, err = cidrset.NewCIDRSet(v6CIDR, option.Config.NodeCIDRMaskSizeIPv6)
		if err != nil {
			return fmt.Errorf("unable to create IPv6 pod CIDR: %s", err)
		}
	}
	cnui := &ciliumNodeUpdateImplementation{}

	// nodeManager := ipam.NewNodesPodCIDRManager(v4CIDRSet, v6CIDRSet, cnui, ipamTriggerMetrics)
	ipam.NewNodesPodCIDRManager(v4CIDRSet, v6CIDRSet, cnui, ipamTriggerMetrics)

	return nil
}
