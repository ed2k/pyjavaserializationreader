{{{
if __name__ == '__main__':
    import dpkt.pcap as pcap
    import dpkt.dpkt as dpkt
    import sys
    import dpkt.ethernet as ethernet
    import dpkt.ip as ip
    import jser
    jser._debug_ = jser.WorkingTable()
    
    pcapfile = pcap.Reader(file(sys.argv[1]))
    #print 'data link type', pcapfile.datalink()
    for (t,buf) in pcapfile:
        eth = ethernet.Ethernet(buf)
        #print 'eth',[eth.src],[eth.dst],'type', hex(eth.type)
        if eth.type != ethernet.ETH_TYPE_IP: continue
        #print [eth.data]
        ipp = eth.data
        #print 'ip',[ipp.src], [ipp.dst],ipp.p
        if not ipp.p in [ip.IP_PROTO_TCP,ip.IP_PROTO_UDP]:continue
        #TODO: handle udp case
        tcpp = ipp.data
        if  31234 != tcpp.sport :continue
        if len(tcpp.data) == 0 : continue 
        #print 'tcp',tcpp.sport,tcpp.dport
        #print [tcpp.data]
        try:
           print '\n-----ccc----------------------------'
           print dpkt.hexdump(tcpp.data[:64])
           # we don't save anything before the decoding
           # assume the decoding will parse something
           j = jser.JSER(tcpp.data) 
        except IndexError,dpkt.NeedData:
            pass
            #for x in jser._debug_.call_stack:
            #    print x.index, x.className()
            #print hex(jser._debug_.saved_handle_cnt)
            #print dpkt.hexdump(jser._debug_.left_over[:64])
            #sys.exit()

}}}