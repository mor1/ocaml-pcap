type metadata = {
  filename: string;
  filesize: int;
}

val of_filename: string -> metadata * (Pcap.fh * Pcap.t Cstruct.iter)
