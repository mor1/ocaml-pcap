(** Format `Cstruct.t` *)
let to_string sep buf =
  let open Printf in
  let line_len = 16 in

  let line bs =
    let line = ref "" in
    for i = 0 to (min line_len (Cstruct.len bs)) - 1 do
      if i > 0 && i mod 8 == 0 then line := !line ^ " ";
      let c = Cstruct.get_uint8 bs i in
      line :=
        if (Char.code ' ' <= c) && (c <= Char.code '~') then
          sprintf "%s %c." !line (Char.chr c)
        else
          sprintf "%s%02x." !line c
    done;
    !line
  in

  let rec fold f acc = function
    | buf when Cstruct.len buf < line_len ->
      sprintf "%s%s%s" acc sep (line buf)
    | buf ->
      fold f (f acc buf) (Cstruct.shift buf line_len)
  in

  fold
    (fun a v -> sprintf "%s%s%s" a sep (line v))
    ""
    buf
