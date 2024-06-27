/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

//------------------------------------------- Not working
package face

import (
	"fmt"
	"net"
	"runtime"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/named-data/YaNFD/core"
	"github.com/named-data/YaNFD/face/impl"
	"github.com/named-data/YaNFD/ndn"
	"github.com/named-data/YaNFD/ndn/tlv"
)

// UnicastEthernetTransport is a Unicast Ethernet transport.
type UnicastEthernetTransport struct {
	pcap           impl.PcapHandle
	shouldQuit     chan bool
	remoteAddr     net.HardwareAddr
	localAddr      net.HardwareAddr
	restartReceive chan interface{} // Used to restart receive after reactivating PCAP handle
	packetSource   *gopacket.PacketSource
	transportBase
}

// MakeUnicastEthernetTransport creates a new Unicast Ethernet transport.
func MakeUnicastEthernetTransport(remoteURI *ndn.URI, localURI *ndn.URI) (*UnicastEthernetTransport, error) {
	// Validate URIs
	if !remoteURI.IsCanonical() || remoteURI.Scheme() != "ether" || !localURI.IsCanonical() ||
		localURI.Scheme() != "dev" {
		return nil, core.ErrNotCanonical
	}

	t := new(UnicastEthernetTransport)
	t.makeTransportBase(remoteURI, localURI, PersistencyPermanent, ndn.NonLocal, ndn.PointToPoint, tlv.MaxNDNPacketSize)
	t.shouldQuit = make(chan bool, 1)
	var err error
	t.remoteAddr, err = net.ParseMAC(remoteURI.Path())
	if err != nil {
		core.LogError(t, "Unable to parse MAC address ", remoteURI.Path(), ": ", err)
		return nil, err
	}
	t.restartReceive = make(chan interface{}, 1)

	if err = t.activateHandle(); err != nil {
		return nil, err
	}

	t.changeState(ndn.Up)

	return t, nil
}

func (t *UnicastEthernetTransport) activateHandle() error {
	// Get interface
	iface, err := net.InterfaceByName(t.localURI.Path())
	if err != nil {
		core.LogError(t, "Unable to get local interface ", t.localURI.Path(), ": ", err)
		return err
	}
	t.localAddr = iface.HardwareAddr

	// Set scope
	t.scope = ndn.NonLocal

	t.pcap, err = impl.OpenPcap(t.localURI.Path(),
		// fmt.Sprintf("ether proto %d and ether dst %s and not ether src %s and not vlan",
		// 	ndnEtherType, t.remoteAddr, t.localAddr),
		fmt.Sprintf("ether proto %d and ether dst %s and ether src %s and not vlan",
			ndnEtherType, t.localAddr, t.remoteAddr),
	)
	if err != nil {
		return err
	}

	t.packetSource = gopacket.NewPacketSource(t.pcap, t.pcap.LinkType())
	t.restartReceive <- nil

	return nil
}

func (t *UnicastEthernetTransport) String() string {
	return "UnicastEthernetTransport, FaceID=" + strconv.FormatUint(t.faceID, 10) +
		", RemoteURI=" + t.remoteURI.String() + ", LocalURI=" + t.localURI.String()
}

// SetPersistency changes the persistency of the face.
func (t *UnicastEthernetTransport) SetPersistency(persistency Persistency) bool {
	if persistency == t.persistency {
		return true
	}

	if persistency == PersistencyPermanent {
		t.persistency = persistency
		return true
	}

	return false
}

// GetSendQueueSize returns the current size of the send queue.
func (t *UnicastEthernetTransport) GetSendQueueSize() uint64 {
	// TODO: Unsupported for now
	return 0
}

func (t *UnicastEthernetTransport) sendFrame(frame []byte) {
	if len(frame) > t.MTU() {
		core.LogWarn(t, "Attempted to send frame larger than MTU - DROP")
		return
	}

	// Wrap in Ethernet frame
	ethHeader := layers.Ethernet{
		SrcMAC:       t.localAddr,
		DstMAC:       t.remoteAddr,
		EthernetType: layers.EthernetType(ndnEtherType),
	}
	ethFrame := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(ethFrame, gopacket.SerializeOptions{}, &ethHeader, gopacket.Payload(frame))

	// Write to PCAP handle
	core.LogDebug(t, "Sending frame of size ", len(ethFrame.Bytes()))
	err := t.pcap.WritePacketData(ethFrame.Bytes())
	if err != nil {
		core.LogWarn(t, "Unable to write frame - DROP")
		t.activateHandle()
		return
	}
	t.nOutBytes += uint64(len(frame))
}

func (t *UnicastEthernetTransport) runReceive() {
	if lockThreadsToCores {
		runtime.LockOSThread()
	}

	for {
		core.LogDebug(t, "Waiting for packet at ", t.localAddr)
		select {
		case packet := <-t.packetSource.Packets():
			core.LogDebug(t, "Received packet at ", t.localAddr)
			core.LogDebug(t, "Received ", len(packet.Data()), " bytes from ", packet.LinkLayer().LinkFlow().Src().String())

			// Extract network layer (NDN)
			ndnLayer := packet.LinkLayer().LayerPayload()
			t.nInBytes += uint64(len(ndnLayer))

			if len(ndnLayer) > tlv.MaxNDNPacketSize {
				core.LogWarn(t, "Received too much data without valid TLV block - DROP")
				continue
			}

			// Send up to link service
			// t.linkService.handleIncomingFrame(ndnLayer)
			
			// FaceTable.Add(t.linkService)
			// go t.linkService.Run(ndnLayer)
			newLinkService := MakeNDNLPLinkService(t, MakeNDNLPLinkServiceOptions())
			FaceTable.Add(newLinkService)
			go newLinkService.Run(ndnLayer)

		case <-t.shouldQuit:
			core.LogDebug(t, "Receive thread is quitting")
			return
		case <-t.restartReceive:
			// This causes the recieve thread to use the new packet source from a new PCAP handle
			continue
		}
	}
}

func (t *UnicastEthernetTransport) changeState(new ndn.State) {
	if t.state == new {
		return
	}

	core.LogInfo(t, "state: ", t.state, " -> ", new)
	t.state = new

	if t.state != ndn.Up {
		core.LogInfo(t, "Closing Unicast Ethernet transport")
		t.shouldQuit <- true
		// Explicit close seems to be broken for now: https://github.com/google/gopacket/issues/862
		/*if t.pcap != nil {
			t.pcap.Close()
		}*/

		// Stop link service
		t.linkService.tellTransportQuit()

		FaceTable.Remove(t.faceID)
		t.hasQuit <- true
	}
}
