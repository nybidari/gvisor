// Copyright 2019 The gVisor Authors.
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

package iptables

import (
	"fmt"
	"net"
	"time"
)

const (
	dropPort         = 2401
	acceptPort       = 2402
	redirectPort     = 42
	sendloopDuration = 2 * time.Second
	network          = "udp4"
)

func init() {
	RegisterTestCase(FilterInputDropUDP{})
	RegisterTestCase(FilterInputDropUDPPort{})
	RegisterTestCase(FilterInputDropDifferentUDPPort{})
	RegisterTestCase(FilterInputRedirectUDPPort{})
}

// FilterInputDropUDP tests that we can drop UDP traffic.
type FilterInputDropUDP struct{}

// Name implements TestCase.Name.
func (FilterInputDropUDP) Name() string {
	return "FilterInputDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDP) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	if err := listenUDP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDP) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// FilterInputDropUDPPort tests that we can drop UDP traffic by port.
type FilterInputDropUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropUDPPort) Name() string {
	return "FilterInputDropUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDPPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on dropPort.
	if err := listenUDP(dropPort, sendloopDuration); err == nil {
		return fmt.Errorf("packets on port %d should have been dropped, but got a packet", dropPort)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDPPort) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, dropPort, sendloopDuration)
}

// FilterInputDropDifferentUDPPort tests that dropping traffic for a single UDP port
// doesn't drop packets on other ports.
type FilterInputDropDifferentUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropDifferentUDPPort) Name() string {
	return "FilterInputDropDifferentUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropDifferentUDPPort) ContainerAction(ip net.IP) error {
	if err := filterTable("-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", dropPort), "-j", "DROP"); err != nil {
		return err
	}

	// Listen for UDP packets on another port.
	if err := listenUDP(acceptPort, sendloopDuration); err != nil {
		return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropDifferentUDPPort) LocalAction(ip net.IP) error {
	return sendUDPLoop(ip, acceptPort, sendloopDuration)
}

// FilterInputRedirectUDPPort tests that packets are redirected to different port.
type FilterInputRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputRedirectUDPPort) Name() string {
        return "FilterInputRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputRedirectUDPPort) ContainerAction(ip net.IP) error {
        if err := filterTable("-t", "nat", "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redirectPort)); err != nil {
		return err
	}

	if err := listenUDP(redirectPort, sendloopDuration); err != nil {
	        return fmt.Errorf("packets on port %d should be allowed, but encountered an error: %v", acceptPort, redirectPort, err)
	}

	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputRedirectUDPPort) LocalAction(ip net.IP) error {
        return sendUDPLoop(ip, acceptPort, sendloopDuration)
}
