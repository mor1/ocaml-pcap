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
open Copts

(* conditional printers, conditioned on copts *)
let pr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.fprintf stderr
  | Verbose -> Printf.fprintf stderr
let vpr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.ifprintf stderr
  | Verbose -> Printf.fprintf stderr

let print copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let open Printf in
  let files = List.map Seq.of_filename filenames in
  List.iter (fun (file, (fileheader,packets)) ->
      printf "\
        ### START: filename:%s size:%d\n\
        %s\n%!" file.Seq.filename file.Seq.filesize (Pcap.fh_to_str fileheader);
      let npackets =
        Cstruct.fold (fun acc pkt ->
            let Pcap.PCAP(h, p, _) = pkt in
            let pcap_to_str, pkt_to_str =
              match copts.verbosity with
              | Quiet | Normal -> Pcap.to_str, Ps.Packet.to_str
              | Verbose -> Pcap.to_string, Ps.Packet.to_string
            in
            printf "%d: PCAP(%s)%s\n%!" acc (pcap_to_str h) (pkt_to_str p);
            acc+1
          ) packets 0
      in
      printf "### END: npackets:%d\n%!" npackets
    ) files

let reform copts =
  let _pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress

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
  mutable first: time_t;
  mutable last: time_t;
}
let statistics_to_string s =
  Printf.sprintf
    "npackets:%ld bytes:%ld capbytes:%ld first:%s last:%s"
    s.packets s.bytes s.capbytes
    (time_t_to_string s.first) (time_t_to_string s.last)

let statistics copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let files = List.map Seq.of_filename filenames in
  List.iter (fun (file, (fileheader, packets)) ->
      let zero = { packets=0l;
                   bytes=0l;
                   capbytes=0l;
                   first={secs=0l;usecs=0l};
                   last={secs=0l;usecs=0l}
                 }
      in
      let stats =
        Cstruct.fold (fun s pkt ->
            let open Pcap in
            let PCAP(h,_,_) = pkt in
            s.packets <- Int32.add s.packets 1l;
            s.bytes <- Int32.add s.bytes h.len;
            s.capbytes <- Int32.add s.capbytes h.caplen;
            s
          ) packets zero
      in
      Printf.printf "filename:%s %s\n%!"
        file.Seq.filename (statistics_to_string stats)
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
