#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink

class MyTopology(Topo):
    """
    A basic topology
    """
    def __init__(self):
        Topo.__init__(self)
        
        # Adding switches
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')

        # Adding hosts with IP addresses
        siri = self.addHost('Siri', ip='10.1.0.1')
        desktop = self.addHost('Desktop', ip='10.2.0.1')
        fridge = self.addHost('Fridge', ip='10.2.0.2')
        alexa = self.addHost('Alexa', ip='10.3.0.1')
        smarttv = self.addHost('SmartTV', ip='10.3.0.2')
        server = self.addHost('Server', ip='10.4.0.1')

        # Connecting hosts to switchesxs
        self.addLink(siri, switch1)
        self.addLink(desktop, switch2)
        self.addLink(fridge, switch2)
        self.addLink(alexa, switch3)
        self.addLink(smarttv, switch3)
        self.addLink(server, switch4)

        # Connecting switches together
        self.addLink(switch1, switch2)
        self.addLink(switch2, switch3)
        self.addLink(switch3, switch4)

if __name__ == '__main__':
    topo = MyTopology()  # Creates the custom topology
    net = Mininet(topo=topo)  # Loads the custom topology
    net.start()  # Starts Mininet

    # Commands here will run on the simulated topology
    CLI(net)

    net.stop()  # Stops Mininet