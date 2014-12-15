(*
 * Copyright (c) 2014 Richard Mortier <mort@cantab.net>
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

open Lwt

type 'a t = 'a Cstruct.iter

type metadata = {
  filename: string;
  filesize: int;
}

let kB = 1024
let mB = 1024*kB
let buffer_size = 4*mB

let of_filename filename =
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf =
    Bigarray.(Array1.map_file fd char c_layout false (-1))
    |>  Cstruct.of_bigarray
  in
  let filesize = Cstruct.len buf in

  let open Ocap in
  match Pcap.iter buf (Ps.Demux.(eth_demux () ethertype_demux)) with
  | None -> failwith "PCAP error: failed to read magic number!"
  | Some (pcap_fileheader, pcap_packets) ->
    ({ filename; filesize }, (pcap_fileheader, pcap_packets))

let fold f acc seq =
  Cstruct.fold f seq acc

let iter f seq =
  fold (fun () -> f) () seq
