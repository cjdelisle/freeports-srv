'use strict';
const PCap = require("pcap");
const NetChecksum = require('netchecksum');

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

    //const udpCsum = pktBin.slice(i, i += 2);
    i += 2 // csum is unused...

    const content = pktBin.slice(i, i += 8);

    if (udpLen.toString('hex') !== '0010') { throw new Error(); }
    if (content.toString('utf8') !== 'FREEPORT') { throw new Error(); }


    // flip src and dest ip addresses
    const ipFullHdr = Buffer.concat([ipHdr, ipDst, ipSrc]);

    // bring up the TTL back to 64
    ipFullHdr[8] = 64;

    // recalc the ip checksum
    ipFullHdr[10] = 0;
    ipFullHdr[11] = 0;
    ipFullHdr.writeUInt16BE(NetChecksum.raw(ipFullHdr), 10);

    const replyContent = new Buffer("PORTFREE");

    const udpCsum = new Buffer(2);
    udpCsum.writeUInt16BE(NetChecksum.udp4(ipDst, ipSrc, udpDst, udpSrc, replyContent));

    const newPkt = Buffer.concat([
        ethSrc, ethDst, ethertype, // flip src and dest ether addresses
        ipFullHdr,
        udpDst, udpSrc, udpLen, udpCsum, // flip src and dest udp ports.
        replyContent
    ]);

    session.inject(newPkt);
};

const main = (argv) => {
    let device;
    if (argv.length === 3) { device = argv[2]; }
    const sess = PCap.createSession(device, MATCHER);
    console.error("Listening on " + sess.device_name);
    sess.on('packet', (raw) => {
        const packet = PCap.decode.packet(raw);
        const ip = packet.payload.payload;
        const udp = ip.payload;
        console.log(ip.saddr.addr.join('.') + ':' + udp.sport + ' -> ' +
            ip.daddr.addr.join('.') + ':' + udp.dport);

        reply(raw.buf, sess);
    });
};
main(process.argv);
