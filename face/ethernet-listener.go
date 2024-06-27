// ethernet-listener.go

package face

import (
    "fmt"
    "net"

    "github.com/named-data/YaNFD/core"
    "github.com/google/gopacket"
    // "github.com/google/gopacket/layers"
    "github.com/named-data/YaNFD/face/impl"
    "github.com/named-data/YaNFD/ndn"
)

// EthernetListener listens for incoming Ethernet connections.
type EthernetListener struct {
    conn            impl.PcapHandle
    iface           *net.Interface
    localURI        *ndn.URI
    HasQuit         chan bool
    restartReceive  chan interface{} 
    packetSource    *gopacket.PacketSource
}

// MakeEthernetListener constructs an EthernetListener.
func MakeEthernetListener(localURI *ndn.URI) (*EthernetListener, error) {
    localURI.Canonize()
    if !localURI.IsCanonical() || localURI.Scheme() != "dev" {
        return nil, core.ErrNotCanonical
    }

    iface, err := net.InterfaceByName(localURI.Path())
    if err != nil {
        core.LogError(nil, "Unable to get local interface ", localURI.Path(), ": ", err)
        return nil, err
    }


    l := &EthernetListener{
        localURI: localURI,
        iface: iface,
        HasQuit: make(chan bool, 1),
    }
    return l, nil
}

func (l *EthernetListener) createListener() (*gopacket.PacketSource, error) {
    var err error
    l.restartReceive = make(chan interface{}, 1)
    l.conn, err = impl.OpenPcap(l.localURI.Path(),
        fmt.Sprintf("ether proto %d and ether dst %s", ndnEtherType, l.iface.HardwareAddr),
    )
    if err != nil {
        core.LogError(l, "Unable to open pcap handle: ", err)
        l.HasQuit <- true
        return nil, err
    }

    return gopacket.NewPacketSource(l.conn, l.conn.LinkType()), nil
}

func (l *EthernetListener) String() string {
    return "EthernetListener, " + l.localURI.String()
}

// Run starts the Ethernet listener.
func (l *EthernetListener) Run() {
    // Logic to listen for Ethernet traffic
    // This could involve setting up a PCAP handle similar to UnicastEthernetTransport.activateHandle()
    // and continuously reading packets from it.

    // Create listener
    var err error
    l.packetSource, err = l.createListener()
    if err != nil {
        core.LogError(l, "Unable to create listener: ", err)
        return
    }
    // Run accept loop
    // defer func() {
    //     l.conn.Close()
    //     l.HasQuit <- true
    // }()

    for {
        select{
        case packet := <-l.packetSource.Packets():
            remoteAddrEndpoint := packet.LinkLayer().LinkFlow().Dst()
            remoteAddr, err := net.ParseMAC(remoteAddrEndpoint.String())
            if err != nil {
                core.LogError(l, "Unable to parse MAC address: ", err)
                continue
            }
            var remoteURI *ndn.URI
            remoteURI = ndn.MakeEthernetFaceURI(remoteAddr)
            remoteURI.Canonize()
            if !remoteURI.IsCanonical() {
                core.LogWarn(l, "Unable to create face from ", remoteAddr, ": could not create canonical URI")
                continue
            }
    
            core.LogTrace(l, "Received packet from ", remoteURI)
    
            newTransport, err := MakeUnicastEthernetTransport(remoteURI, l.localURI)
            if err != nil {
                core.LogError(l, "Unable to create transport: ", err)
                continue
            }
            newLinkService := MakeNDNLPLinkService(newTransport, MakeNDNLPLinkServiceOptions())
            FaceTable.Add(newLinkService)
            core.LogDebug(l, "Called from ethernet-listener.go: ", newLinkService.String(), " added to FaceTable.")
            go newLinkService.Run(packet.LinkLayer().LayerPayload())
        case <-l.restartReceive:
            continue
        }
    }
}