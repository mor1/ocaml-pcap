`ocaml-pcap`
============

Ocaml code for generating and analysing PCAP (`tcpdump` packet capture) files.
Based off Anil Madhavapeddy's "cstruct" example code.

## Wishlist

### Per-packet

+ common options:
  + verbosity
  + debug
  + progress-- filename, index? (commented out!)

+ cli of the form `ocap [command] [options]` per cmdliner
  + reform
    + single input (split); multiple inputs (mergesort)
    + options: output control by filesize (bytes), #packets, duration (secs);
      input control by timerange, index range (if single input)
  + print
    + single line summary (+ tcpdump compat mode + tshark compat mode)
    + formatted multi-line summary
    + options: header field (commented out!); hex payload dump when verbose
  + statistics
    + count, size distribution, duration, iat distribution
    + (treat packet stats as special case of flow stats with single flow)
    + options: packet, 2-tuple, 4-tuple, 5-tuple, uni-/bi-directional;
      per-period
  + hosts
    + dump /etc/hosts format name info using DNS from trace
  + diff
    + compare two input pcap files semantically, selectively ignoring:
      + pcap: timestamps; all but caplen of payload
      + eth: ?
      + ip4: ipid, checksum, ?
      + ...

+ protocol specific subcommands
  + common
    + timestamp format: epoch, ctime, relative
  + ip
  + tcp
    + absolute vs relative seqno/ackno
  + dns
    + extract timestamped name-translations requested by specified sources
  + http
    + extract timestamped addr / Host (if available) / URLs


### Incrementalism

common pattern is pipeline element wants to process stdin to stdout, but take a
first (or N) parameter(s) that represents some (serialised) state, either to
update that state or to use it in the processing
