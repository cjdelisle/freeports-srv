const PCap = require("pcap");

// UDP packets with the content 'FREEPORT'
const MATCHER = "udp and udp[8:4] = 0x46524545 and udp[12:4] = 0x504f5254 and udp[4:2] = 0x0010";

const reply = (pktBin, session) => {

    let i = 0;
    const ethDst = pktBin.slice(i, i += 6);
    const ethSrc = pktBin.slice(i, i += 6);
    const ethertype = pktBin.slice(i, i += 2);
    const ipHdr = pktBin.slice(i, i += 12);
    const ipSrc = pktBin.slice(i, i += 4);
    const ipDst = pktBin.slice(i, i += 4);
    const udpSrc = pktBin.slice(i, i += 2);
    const udpDst = pktBin.slice(i, i += 2);
    const udpLen = pktBin.slice(i, i += 2);
    const udpCsum = pktBin.slice(i, i += 2); //*/ i += 2 // csum is unused...
    const content = pktBin.slice(i, i += 8);

    if (udpLen.toString('hex') !== '0010') { throw new Error(); }
    if (content.toString('utf8') !== 'FREEPORT') { throw new Error(); }

    // clear the ip checksum
    ipHdr[10] = 0;
    ipHdr[11] = 0;

    // bring up the TTL back to 64
    ipHdr[8] = 64;

    const newPkt = Buffer.concat([
        ethSrc, ethDst, ethertype, // flip src and dest ether addresses

        ipHdr, ipDst, ipSrc, // flip src and dest ip addresses

        udpDst, udpSrc, udpLen, new Buffer([0,0]), // flip src and dest udp ports and zero csum.

        new Buffer("PORTFREE")
    ]);

    session.inject(newPkt);
}

const main = (argv) => {
    let device;
    if (argv.length === 3) { device = argv[2]; }
    const sess = PCap.createSession(device, MATCHER);
    console.error("Listening on " + sess.device_name);
    sess.on('packet', (raw) => {
        const packet = PCap.decode.packet(raw);
        const ip = packet.payload.payload;
        const udp = ip.payload;
        console.log(ip.saddr.addr.join('.') + ':' + udp.sport);

        reply(raw.buf, sess);
    });
};
main(process.argv);
