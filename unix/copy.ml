(*
 * Copyright (c) 2013 Richard Mortier <mort@cantab.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Printf
open Operators
open Capture
open Capture.Pcap

let write fd buf =
  let s = Cstruct.to_string buf in
  Unix.write fd s 0 (String.length s)

let create_pcap filename fh =
  let buf = Cstruct.create Pcap.sizeof_pcap_header in
  let open Pcap.LE in
  set_pcap_header_magic_number buf fh.magic_number;
  set_pcap_header_version_major buf fh.version_major;
  set_pcap_header_version_minor buf fh.version_minor;
  set_pcap_header_thiszone buf fh.timezone;
  set_pcap_header_sigfigs buf fh.sigfigs;
  set_pcap_header_snaplen buf fh.snaplen;
  set_pcap_header_network buf fh.network;

  let fd = Unix.(openfile filename [O_WRONLY; O_CREAT; O_TRUNC] 0o644) in
  let n = write fd buf in
  printf "### %s <%d>\n%!" (Pcap.fh_to_string fh) n;
  fd

let filter fd n = function
  | PCAP(h, p, bs) ->
    let w = write fd bs in
    printf "%d: PCAP(%s)%s <%d>\n%!" n (Pcap.to_str h) (Packet.to_str p) w;
    n+1

let parse buf =
  match Pcap.iter buf Demux.(eth_demux () ethertype_demux) with
    | None -> fprintf stderr "not pcap\n%!"
    | Some (fileheader, packets) ->
      let fd = create_pcap "output.pcap" fileheader in
      let n = Cstruct.fold (filter fd) packets 0 in
      printf "### done! n=%d\n%!" n;
      Unix.close fd

(** convert [filename] string to a buffer by opening and mapping file *)
let filename_to_buf filename =
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  let buf = Cstruct.of_bigarray buf in
  buf

let _ =
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files) "Dump the contents of pcap files";

  let files = List.rev !files in
  List.iter (fun file -> file |> filename_to_buf |> parse) files;
