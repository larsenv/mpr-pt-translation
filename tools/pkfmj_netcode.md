# pkfmj netcode — save upload / download

Notes on My Pokémon Ranch's online save sync, reverse engineered statically
from the USA main DOL (`tools/00000001.app`). All addresses are virtual and
verified against that build; use `dolnet.py` to re-derive them for any other
region or revision.

## Endpoints

```
https://pkfmj.nintendo.co.jp/RVL-XXXX/%016lld/open     @0x8062fc0c
https://pkfmj.nintendo.co.jp/RVL-XXXX/%016lld/get      @0x8062fc40
https://pkfmj.nintendo.co.jp/RVL-XXXX/%016lld/put      @0x8062fd0c
https://pkfmj.nintendo.co.jp/RVL-XXXX/%016lld/close    @0x8062ff60
```

`RVL-XXXX` is a literal placeholder — nothing in the binary substitutes it.
`%016lld` is a 64-bit console ID fetched by `0x80418330`, which reads the
NWC24 config object at `-0x1188(r13)` (fields +0x08/+0x0c) and falls back to
lomem `0x800031c0`/`0x800031c4`.

The transport is stock RVL_SDK: NHTTP over SSL, with NWC24 for connection
setup.

## The generic worker thread — `0x8034cd88`

Every request goes through one thread entry. Its parameter struct:

| offset | field |
| ------ | ----- |
| +0x00  | URL format string |
| +0x04  | POST body length |
| +0x08  | POST body pointer |
| +0x0c  | destination buffer |
| +0x10  | `&outSize` |
| +0x14  | 0x1000 scratch buffer for NHTTP |
| +0x18  | `&okFlag` (one byte) |

Sequence:

1. NWC24 / net startup — `0x8044d37c`, `0x8044d640`
   (cleanup `0x8044da74` / `0x8044d544`).
2. `NHTTPStartup` (`0x8042bd74`), thread priority 0x12.
3. Fetch the 64-bit ID (`0x80418330`) and `sprintf` (`0x800c1cb8`) the URL.
4. `NHTTPCreateRequest` (`0x8042b7e4`). **The method is chosen purely by
   whether the body length is nonzero** — `srwi((-len | len), 31)` yields 0
   for GET, 1 for POST. Max response size 0x100000.
5. Options `0x8042c15c` / `0x8042c100`, then `NHTTPAddHeaderField`
   (`0x8042be24`) with `Content-Type:` + the multipart boundary — sent on
   *every* request, GET included.
6. If there is a body, `NHTTPAddPostDataRaw` (`0x8042bee8`).
7. Send (`0x8042bbb4`, `0x8042bac8`); require state >= 4 (`0x8042bc40`) and
   HTTP status exactly 200 (`0x8042c0a0`).
8. Response body via `0x8042bc8c`, copied with `memcpy` (`0x80004338`)
   clamped to `*outSize`; the `Content-Length` response header is read with
   `0x8042bfb0` and parsed by `strtoul` (`0x805c5964`).
9. `okFlag = 1` only after a 200.

Threads are plain `OSCreateThread` (`0x80540f6c`) / `OSResumeThread`
(`0x805415d4`), with the caller spinning on `OSIsThreadTerminated`
(`0x805409a4`). 0x1000 stack, priority 0x10.

## Upload — `0x8034d548` (`/put`)

Copies a 0xD3-byte multipart template from `0x805d54b8`:

```
-----------------------------7d833fb680cc2
Content-Disposition: form-data; name="data_entry[savedata]"; filename="C:\savedata.bin"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary

<save payload>
-----------------------------7d833fb680cc2--
```

followed by a 0x30-byte trailer built on the stack at `sp+0xf0`. It then
fills the worker param struct at `sp+0xa0` with the body pointer and length
set, so the worker issues a POST.

The hardcoded boundary matches the `Content-Type` header string at
`0x8062fc84`.

## Download — `0x8034e494` (`/get`, then `/close`)

Allocates a 0xF8000 destination buffer (`0x80379fcc`, 0x20 alignment) and
runs the `/get` worker. On success it validates the blob:

- total size >= 0x20
- header word 0 == `*(0x80537eb4())`
- payload length < 0x7C000
- total size >= payload length + 0x20

Any failure clears the ok byte and returns 1. It then runs a second worker
for `/close`. The orchestrator / caller is `0x8034dc50`.

`/open` and `/get` are also reachable through a small dispatcher at
`0x8034c9f0` (mode 1 = open, mode 2 = get) via the request helper
`0x8034cb98`.

## Loose ends

`nand:savedata.bin` (`0x8062fcec`) and `nand:backup/savedata.bin`
(`0x8062fd00`) have no code references anywhere in the DOL — dead or
debug-only.

When chasing these strings in a disassembler, note that they are loaded as
`addi rX, rBase, off` off a base pointer (`0x8062ef88`) held in r29/r30 for
the whole function, not as a self-contained `lis`/`addi` pair. `dolnet.py
xref` tracks the base register so it finds both forms.
