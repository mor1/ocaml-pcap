(*
 * Copyright (C) 2015 Richard Mortier <mort@cantab.net>
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

open Packet

type t = Dns.Packet.t

let to_str t = Printf.sprintf "DNS(%s)" (Dns.Packet.to_string t)

let to_string t =
  let open DP in
  Printf.sprintf "DNS(id:%04x detail:%s)"
    t.id (detail_to_string t.detail)

(* label cache observed so far in this packet *)
let labels = Hashtbl.create 32

let parsen base f n buf =
  let rec parsen_ base acc n buf =
    match n with
    | 0 -> acc, (base,buf)
    | _ ->

      (* XXX need to catch Failure exn from `f` here: either parse failure, or
         due to `Cstruct.shift` when returning `buf` *)

      let r, (base,buf) = f labels base buf in
      parsen_ base (r :: acc) (n-1) buf
  in
  parsen_ base [] n buf

let parse buf =
  (* XXX daft; first thing Dns.parse does is Cstruct.of_bigarray *)

(*
  let buf = Cstruct.to_bigarray buf in
  Printf.printf "DNS!\n%!";
*)

  (* XXX move to CPS some time soon. please. *)

  let open DP in
  trap_exn get_h_id      buf >>= fun id      ->
  trap_exn get_h_detail  buf >>= fun detail  ->
  trap_exn get_h_qdcount buf >>= fun qdcount ->
  trap_exn get_h_ancount buf >>= fun ancount ->
  trap_exn get_h_nscount buf >>= fun nscount ->
  trap_exn get_h_arcount buf >>= fun arcount ->

  (* record base so that we can unpick label compression when parsing *)
  trap_exn (shift sizeof_h) buf >>= fun buf ->

  let parsen = parsen sizeof_h in
  trap_exn (parsen parse_question qdcount) buf >>= fun questions buf ->
  trap_exn (parsen parse_rr ancount) buf >>= fun answers buf ->
  trap_exn (parsen parse_rr nscount) buf >>= fun authorities buf ->
  trap_exn (parsen parse_rr adcount) buf >>= fun additionals buf ->

  { id; detail; questions; answers; authorities; additionals }
