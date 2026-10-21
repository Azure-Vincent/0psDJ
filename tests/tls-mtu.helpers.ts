/** MSS values advertised in SYN segments of a tcpdump listing. */
export function parseTcpdumpMss(output: string): number[] {
  return [...output.matchAll(/Flags \[S\], .*options \[mss (\d+)/g)].map((m) => Number(m[1]));
}
