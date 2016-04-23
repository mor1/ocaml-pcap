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

open Copts
open Rresult_infix

(* conditional printers, conditioned on copts *)
let pr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.fprintf stderr
  | Verbose -> Printf.fprintf stderr
let vpr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.ifprintf stderr
  | Verbose -> Printf.fprintf stderr

let error bt buf =
  failwith
    (Printf.sprintf "ERR: %s\n%s\n%!"
       (Printexc.raw_backtrace_to_string bt) (Buf.to_string buf))

let print copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let open Printf in
  let files = List.map Trace.of_filename filenames in
  let ocap_to_str, pkt_to_str =
    match copts.verbosity with
    | Quiet | Normal -> Ocap.to_str, Packet.to_str
    | Verbose -> Ocap.to_string, Packet.to_string
  in
  List.iter (fun (file, packets) ->
      printf "### START: filename:%s size:%d\n%!"
        file.Trace.filename file.Trace.filesize;
      let result =
        Seq.fold (fun acc -> function
            | `PCAP _ | `ERF _ -> failwith "invalid type, expected PKT!"
            | `Eof -> acc
            | `PKT (h, p, _) ->
              printf "%d: PKT(%s)%s\n%!" acc (ocap_to_str h) (pkt_to_str p);
              acc+1
          ) packets 0
      in
      match result with
      | Ok acc -> printf "### END: npackets:%d\n%!" acc
      | Error (acc, buf, bt) -> printf "%d: ERR\n%!" acc; error bt buf
    ) files

let reform copts filenames ofilename =
  let _pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let write fd buf =
    let s = Cstruct.to_string buf in
    Unix.write fd s 0 (String.length s)
  in

  let creat filename =
    let fd = Unix.(openfile filename [O_WRONLY; O_CREAT; O_TRUNC] 0o644) in
    let buf = Cstruct.create Pcap.sizeof_pcap_header in
    let open Pcap in (* assume LE platform for now *)
    LE.set_pcap_header_magic_number  buf magic_number;
    LE.set_pcap_header_version_major buf major_version;
    LE.set_pcap_header_version_minor buf minor_version;
    LE.set_pcap_header_thiszone      buf 0x0000_0000_l; (* GMT *)
    LE.set_pcap_header_sigfigs       buf 0x0000_0000_l;
    LE.set_pcap_header_snaplen       buf 0x0000_ffff_l;
    LE.set_pcap_header_network       buf 0x0000_0001_l;
    let n = write fd buf in
    assert (n = 24);
    fd
  in

  let write_pcap ofd (h,b,bs) =
    let buf = Cstruct.create Pcap.sizeof_pcap_packet in
    let open Pcap in (* LE platform assumed above *)
    let secs = Int64.(div h.Ocap.usecs 1_000_000_L |> to_int32) in
    let usecs = Int64.(rem h.Ocap.usecs 1_000_000_L |> to_int32) in

    LE.set_pcap_packet_ts_sec buf secs;
    LE.set_pcap_packet_ts_usec buf usecs;
    LE.set_pcap_packet_caplen buf (Int32.of_int h.Ocap.caplen);
    LE.set_pcap_packet_len buf (Int32.of_int h.Ocap.len);

    let n = write ofd buf in assert (n=16);
    let n = write ofd bs in assert (n=Cstruct.len bs);
    ()
  in

  let ofd = creat ofilename in
  let ifds = filenames |> List.map (fun fn ->
      (* assumes all inputs are valid pcap trace files *)
      let (_, ifd) = Trace.of_filename fn in
      ifd
    )
  in

  let streams = List.map (fun ifd -> (ifd (), ifd)) ifds in

  let process streams =
    let cmp (lp,_) (rp,_) =
      let open Ocap in
      match lp, rp with
      | Ok `Eof, _ | Error _, _ -> -1
      | _, Ok `Eof | _, Error _ -> 1
      | Ok (`PKT (lh, _, _)), Ok (`PKT (rh, _, _)) -> compare lh rh
      | Ok _, Ok _ -> failwith "only PKT expected!"
    in

    let rec process_ ss =
      match List.sort cmp ss with
      | [] -> ()
      | (p,s) :: tl ->
        let rest = match p with
          | Error (buf, bt) -> error bt buf
          | Ok `Eof -> tl
          | Ok (`PKT pkt) -> write_pcap ofd pkt; (s (), s) :: tl
          | Ok _ -> failwith "only PKT expected!"
        in process_ rest
    in
    process_ streams
  in
  process streams

type time_t = {
  secs: int32;
  usecs: int32;
}
let time_t_to_string t =
  Printf.sprintf "%ld.%06ld" t.secs t.usecs

type statistics = {
  mutable packets: int32;
  mutable bytes: int32;
  mutable capbytes: int32;
  mutable first: int64;
  mutable last: int64;
}
let statistics_to_string s =
  Printf.sprintf
    "npackets:%ld bytes:%ld capbytes:%ld first:%s last:%s"
    s.packets s.bytes s.capbytes
    (Ocap.usecs_to_string s.first) (Ocap.usecs_to_string s.last)

let statistics copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let files = List.map Trace.of_filename filenames in
  List.iter (fun (file, packets) ->
      let zero = {
        packets=0l;
        bytes=0l;
        capbytes=0l;
        first=0L;
        last=0L
      } in
      let stats = Seq.fold (fun s -> function
          | `PKT(h,_,_) ->
            s.packets <- Int32.add s.packets 1l;
            s.bytes <- Int32.(add s.bytes (of_int h.Ocap.len));
            s.capbytes <- Int32.(add s.capbytes (of_int h.Ocap.caplen));
            if s.first = 0L then s.first <- h.Ocap.usecs;
            s.last <- h.Ocap.usecs;
            s
          | `Eof -> s
          | `PCAP _ | `ERF _ -> failwith "only PKT expected!"
        ) packets zero
      in
      match stats with
      | Ok stats ->
        Printf.printf "filename:%s %s\n%!"
          file.Trace.filename (statistics_to_string stats)
      | Error (stats, buf, bt) ->
        Printf.printf "ERR: %s\n%!" (statistics_to_string stats);
        error bt buf
    ) files

let help copts man_format cmds topic =
  let _pr, _vpr = pr copts, vpr copts in
  match topic with
  | None -> `Help (`Pager, None)
  | Some topic ->
    let topics = "topics" :: "patterns" :: "environment" :: cmds in
    let conv, _ = Cmdliner.Arg.enum (List.rev_map (fun s -> (s, s)) topics) in
    match conv topic with
    | `Error e -> `Error (false, e)
    | `Ok t when t = "topics" -> List.iter print_endline topics; `Ok ()
    | `Ok t when List.mem t cmds -> `Help (man_format, Some t)
    | `Ok t ->
      let page = (topic, 7, "", "", ""), [`S topic; `P "Say something";] in
      `Ok (Cmdliner.Manpage.print man_format Format.std_formatter page)
