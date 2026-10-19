import type { ArpPacket, Packet } from '../../engine/types';
import { packetLength } from '../../engine/sim/network';

function Rows({ rows }: { rows: [string, string | number][] }) {
  return (
    <table>
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}><th style={{ width: '40%' }}>{k}</th><td className="mono">{v}</td></tr>
        ))}
      </tbody>
    </table>
  );
}

const ICMP_NAMES: Record<number, string> = { 0: 'Echo reply', 3: 'Destination unreachable', 8: 'Echo request', 11: 'Time exceeded' };

export function PacketLayers({ packet, arp, l2 }: { packet?: Packet; arp?: ArpPacket; l2?: { src: string; dst: string; note?: string }[] }) {
  return (
    <div>
      {l2 && l2.length > 0 && (
        <details className="layer" open>
          <summary>Ethernet II {l2.length > 1 ? `(${l2.length} hops: the frame is rebuilt at every router)` : ''}</summary>
          <table>
            <thead><tr><th>Segment</th><th>Source MAC</th><th>Destination MAC</th></tr></thead>
            <tbody>
              {l2.map((h, i) => <tr key={i}><td>{h.note ?? `hop ${i + 1}`}</td><td className="mono">{h.src}</td><td className="mono">{h.dst}</td></tr>)}
            </tbody>
          </table>
          <div className="muted small" style={{ padding: '4px 8px' }}>EtherType {arp ? '0x0806 (ARP)' : '0x0800 (IPv4)'}</div>
        </details>
      )}
      {arp && (
        <details className="layer" open>
          <summary>Address Resolution Protocol ({arp.op})</summary>
          <Rows rows={[['Opcode', arp.op === 'request' ? '1 (request)' : '2 (reply)'], ['Sender MAC', arp.senderMac], ['Sender IP', arp.senderIp], ['Target MAC', arp.targetMac], ['Target IP', arp.targetIp]]} />
        </details>
      )}
      {packet && (
        <details className="layer" open>
          <summary>Internet Protocol Version 4, Src: {packet.src}, Dst: {packet.dst}</summary>
          <Rows rows={[
            ['Version / Header length', '4 / 20 bytes'],
            ['Total length', packetLength(packet)],
            ['Identification', `0x${(packet.id & 0xffff).toString(16).padStart(4, '0')}`],
            ['Flags', "0x40, Don't fragment"],
            ['Time to live', `${packet.ttl} (as sent; each router decrements it)`],
            ['Protocol', packet.proto === 'tcp' ? 'TCP (6)' : packet.proto === 'udp' ? 'UDP (17)' : 'ICMP (1)'],
            ['Source address', packet.src],
            ['Destination address', packet.dst],
          ]} />
        </details>
      )}
      {packet?.tcp && (
        <details className="layer" open>
          <summary>Transmission Control Protocol, Src Port: {packet.tcp.sport}, Dst Port: {packet.tcp.dport}, Len: {packet.tcp.len}</summary>
          <Rows rows={[
            ['Source port', packet.tcp.sport],
            ['Destination port', packet.tcp.dport],
            ['Sequence number (raw)', packet.tcp.seq],
            ['Acknowledgment number (raw)', packet.tcp.flags.includes('ACK') ? packet.tcp.ack : '0 (ACK flag not set)'],
            ['Flags', packet.tcp.flags.join(', ')],
            ['Window', packet.tcp.window],
            ['Options', packet.tcp.options ?? '—'],
            ['TCP payload', `${packet.tcp.len} bytes`],
          ]} />
        </details>
      )}
      {packet?.udp && (
        <details className="layer" open>
          <summary>User Datagram Protocol, Src Port: {packet.udp.sport}, Dst Port: {packet.udp.dport}</summary>
          <Rows rows={[['Source port', packet.udp.sport], ['Destination port', packet.udp.dport], ['Length', packet.udp.len + 8]]} />
        </details>
      )}
      {packet?.icmp && (
        <details className="layer" open>
          <summary>Internet Control Message Protocol</summary>
          <Rows rows={[
            ['Type', `${packet.icmp.type} (${ICMP_NAMES[packet.icmp.type] ?? '?'})`],
            ['Code', `${packet.icmp.code}${packet.icmp.description ? ` (${packet.icmp.description})` : ''}`],
            ...(packet.icmp.id !== undefined ? [['Identifier', packet.icmp.id] as [string, number]] : []),
            ...(packet.icmp.seq !== undefined ? [['Sequence', packet.icmp.seq] as [string, number]] : []),
            ...(packet.icmp.quoted ? [['Quoted datagram', `${packet.icmp.quoted.proto.toUpperCase()} ${packet.icmp.quoted.src}:${packet.icmp.quoted.sport ?? ''} → ${packet.icmp.quoted.dst}:${packet.icmp.quoted.dport ?? ''}`] as [string, string]] : []),
          ]} />
        </details>
      )}
      {packet?.app && (
        <details className="layer" open>
          <summary>{packet.app.protocol === 'SSH' ? 'SSH Protocol' : packet.app.protocol === 'DNS' ? 'Domain Name System' : packet.app.protocol === 'DHCP' ? 'Dynamic Host Configuration Protocol (BOOTP)' : 'Data'}{packet.app.encrypted ? ' (encrypted)' : ''}</summary>
          {packet.app.encrypted && (
            <div className="callout warn small" style={{ margin: 6 }}>
              On the wire this is an opaque encrypted packet: an observer sees only its length and timing. The decoded message below is the endpoint's view, shown for teaching. It is not visible in a capture without the session keys.
            </div>
          )}
          <Rows rows={packet.app.fields.map((f) => [f.name, f.value])} />
        </details>
      )}
    </div>
  );
}

export function HexDump({ bytes }: { bytes: Uint8Array }) {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = [...bytes.slice(i, i + 16)];
    const hex = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return <div className="hex">{lines.join('\n')}</div>;
}
