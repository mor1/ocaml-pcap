(*
 * Copyright (C) 2013 Richard Mortier <mort@cantab.net>
 *                    Richard Clegg <richard@richardclegg.org>
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

module Key = struct

end

module Value = struct

end

module State = struct

  module FlowMap = Map.Make(Flow.Key)
  type t = FlowMap

  let to_str flowmap = ""
  let to_string flowmap = ""

  let update flowmap packet = flowmap

  let create () = FlowMap.empty

  let all_keys flowmap = []

  let lookup flowmap key = Flow.Value.create ()

  let remove flowmap key = (key, Flow.Value.create ())

end

let fold f flowmap packets = flowmap
