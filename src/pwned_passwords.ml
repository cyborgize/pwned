
open Devkit
open ExtLib

let log = Log.from "pwned_passwords"

module type IO = sig

  type 'a t

  type fd

  val (>>=) : 'a t -> ('a -> 'b t) -> 'b t

  val return : 'a -> 'a t

  val fail : exn -> 'a t

  val catch : (unit -> 'a t) -> (exn -> 'a t) -> 'a t

  val finalize : (unit -> 'a t) -> (unit -> unit t) -> 'a t

  val fopen : string -> fd t

  val dup : fd -> fd t

  val fseek : fd -> int64 -> unit t

  val ftell : fd -> int64 t

  val read_line : fd -> string option t

  val close : fd -> unit t

end

module type Storage = sig

  type 'a io

  val read : unit -> string option io

  val write : string -> unit io

end

module Lwt : IO with type 'a t = 'a Lwt.t = struct

  type 'a t = 'a Lwt.t

  type fd = {
    fd : Lwt_unix.file_descr;
    io : Lwt_io.input Lwt_io.channel;
  }

  let (>>=) = Lwt.bind

  let return = Lwt.return

  let fail = Lwt.fail

  let catch = Lwt.catch

  let finalize = Lwt.finalize

  let fopen name =
    let%lwt fd = Lwt_unix.openfile name [ O_RDONLY; ] 0 in
    let close () = Lwt_unix.close fd in
    let io = Lwt_io.of_fd ~close ~mode:Input fd in
    Lwt.return { fd; io; }

  let dup { fd; io = _; } =
    let fd = Lwt_unix.dup fd in
    let%lwt (_ : int64) = Lwt_unix.LargeFile.lseek fd 0L Lwt_unix.SEEK_SET in
    let close () = Lwt_unix.close fd in
    let io = Lwt_io.of_fd ~close ~mode:Input fd in
    Lwt.return { fd; io; }

  let fseek { fd = _; io; } pos = Lwt_io.set_position io pos

  let ftell { fd = _; io; } = Lwt.return (Lwt_io.position io)

  let read_line { fd = _; io; } = Lwt_io.read_line_opt io

  let close { fd = _; io; } = Lwt_io.close io

end

module Make(IO : IO)(Storage : Storage with type 'a io = 'a IO.t) = struct

  type t = {
    file : IO.fd;
    ranges : (string * (int64 * int64)) array;
  }

  let (>>=) = IO.(>>=)

  let prefix_size = 4

  let first_range = String.make prefix_size '\000'

  let init_file file =
    let period n = let x = ref (-1) in fun () -> Pervasives.incr x; !x mod n = 0 in
    let period = period 0x100 in
    let rec loop ~first ~last ~prefix nr acc =
      IO.read_line file >>= function
        | None ->
          if period () then log #info "init_file prefix %s [%Ld;%Ld]" prefix first last;
          IO.return (nr, (prefix, (first, last)) :: acc)
        | Some line when String.starts_with line prefix ->
          IO.ftell file >>= fun last ->
          loop ~first ~last ~prefix nr acc
        | Some line ->
          if period () then log #info "init_file prefix %s [%Ld;%Ld]" prefix first last;
          let acc = (prefix, (first, last)) :: acc in
          let prefix = String.slice ~last:prefix_size line in
          IO.ftell file >>= fun new_last ->
          loop ~first:last ~last:new_last ~prefix (nr + 1) acc
    in
    loop ~first:0L ~last:0L ~prefix:first_range 0 [] >>= fun (nr_ranges, ranges') ->
    let ranges = Array.make nr_ranges ("", (0L, 0L)) in
    List.iteri (fun i range -> Array.unsafe_set ranges (nr_ranges - i - 1) range) ranges';
    Storage.write (Marshal.to_string ranges []) >>= fun () ->
    IO.return { file; ranges; }

  let init_storage file s =
    let ranges = Marshal.from_string s 0 in
    IO.return { file; ranges; }

  let init filename =
    IO.fopen filename >>= fun file ->
    IO.catch begin fun () ->
      Storage.read () >>= function
      | Some s -> init_storage file s
      | None -> init_file file
    end begin fun exn ->
      log #warn ~exn "init %s : could not read from storage" filename;
      init_file file
    end

  let find_range ranges prefix =
    let prefix = String.slice ~last:prefix_size prefix in
    let rec binary_search l r =
      let m = l + (r - l) / 2 in
      let (prefix', range) = Array.unsafe_get ranges m in
      match l + 1 = r with
      | true -> range
      | false ->
      match String.compare prefix' prefix with
      | x when x < 0 -> binary_search l m
      | x when x > 0 -> binary_search (m + 1) r
      | _ (* 0 *) -> range
    in
    binary_search 0 (Array.length ranges)

  let rec read_lines file last filter acc =
    IO.ftell file >>= function
    | cur when cur >= last -> IO.return (List.rev acc)
    | _ ->
    IO.read_line file >>= function
    | Some line -> read_lines file last filter (if filter line then line :: acc else acc)
    | None -> IO.return (List.rev acc) (* FIXME warning or error? *)

  let lookup { file; ranges; } prefix =
    assert (String.length prefix >= prefix_size);
    let (first, last) = find_range ranges prefix in
    let filter =
      match String.length prefix > prefix_size with
      | true -> (fun s -> String.starts_with s prefix)
      | false -> (fun _ -> true)
    in
    IO.dup file >>= fun file ->
    IO.finalize begin fun () ->
      IO.fseek file first >>= fun () ->
      read_lines file last filter []
    end begin fun () ->
      IO.close file
    end

  let shutdown { file; ranges = _; } =
    IO.close file

end
