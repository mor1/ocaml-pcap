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

open Rresult_infix

type 'a t = unit -> ('a, string) result
type buf = Cstruct.t

let iter lenfn pfn t =
  let body = ref (Some t) in
  fun () ->
    match !body with
    | Some buf when Cstruct.len buf = 0 ->
      body := None;
      R.ok `Eof

    | Some buf ->
      Demux.trap_exn lenfn buf >>= fun len ->
      Demux.(trap_exn (split len) buf) >>= fun (p, rest) ->
      body := Some rest;
      Demux.trap_exn pfn p

    | None -> R.ok `Eof

let rec fold f next acc = match next () with
  | Ok `Eof -> R.ok acc
  | Ok v -> fold f next (f acc v)
  | Error (buf, bt) -> Error (acc, buf, bt)

let map f iter =
  fun () -> match iter () with
    | Ok v -> R.ok (f v)
    | e -> e
