# openbsm-parser

An OpenBSM audit trail parser utilising dissect.cstruct to parse its binary log files that aims to be usable on Linux as a stand-alone replacement for the existing FreeBSD auditd tooling.

This originated from my internship where I did reseearch into what kind of log sources the FreeBSD operating system had on offer. Out of this research came one log source with a lot of potential: auditd / OpenBSM. There was only one downside; the tooling was primarily designed to function on either macOS or FreeBSD. That's when the idea arose of writing a parser utilising the Fox-IT Dissect framework and its Cstruct plug-in.

Dissect.cstruct allows you to easily parse binary data according to the C struct that defined it. This makes parsing data as easy as `ctrl` + `C` & `ctrl` +`V` as far as the structs are concerned that need to be parsed. This for example looks the following for some of the structs in OpenBSM:

```Python
from dissect.cstruct import cstruct, dumpstruct

cdef = """
/*
 * record byte count       4 bytes
 * version #               1 byte    [2]
 * event type              2 bytes
 * event modifier          2 bytes
 * seconds of time         4 bytes/8 bytes (32-bit/64-bit value)
 * milliseconds of time    4 bytes/8 bytes (32-bit/64-bit value)
 */
typedef struct {
	uint32_t	size;
	uchar		version;
	uint16_t	e_type;
	uint16_t	e_mod;
	uint32_t	s;
	uint32_t	ms;
} au_header32_t;
"""

aurecord = cstruct(endian='>')
aurecord.load(cdef, compiled=True)

# Check the first byte for record type
header_type = fh.read(1)

au_header32_t = aurecord.au_header32_t(fh)
dumpstruct(au_header32_t)
```

This then looks the following in STDOUT:

```
00000000  00 00 00 ac 0b 00 d5 00  00 63 f9 38 7a 00 00 01   .........c.8z...
00000010  19                                                 .

struct au_header32_t:
- size: 0xac
- version: 0xb
- e_type: 0xd5
- e_mod: 0x0
- s: 0x63f9387a
- ms: 0x119
```

## Currently supported

- [x] FreeBSD audit trail types
- [X] macOS audit trail types
- [x] XML output conform to `praudit` XML flag
- [x] Writing output to `.xml` file
- [x] Log of actions and types parsed (even those without XML implementations in the parser)
- [x] Substituting of UID & GID values to their textual counterparts (requires the original system's `passwd` and `group` files)
- [x] Command-line flags to control behaviour (i.e. input/output files, log level, etc.)

## Future update plans

- Better handling of UIDs consisting of `\xFF \xFF \xFF \xFF` so they match that of `praudit` instead of displaying `4294967295`.
  - Currently this specific value is changed to `0` per-case where this happens
- Support for Solaris audit trails

## Performance

Currently the parser is capable of parsing a 46.3 MB audit trail from a macOS system with all auditing options in about ~111 seconds:

```
(.venv311) ❯ python main.py -i new-example-logs/20230224222146.crash_recovery -o new-example-logs/20230224222146.crash_recovery.xml -f output-log.log -g ./system-config/macos/groups-mac -p ./system-config/macos/passwd-mac
[-] Valid file path given; starting parser
Bytes read |********************************| 0 Bytes left - 111 Seconds elapsed
[-] Time spent crunching records: 111.01 seconds
[-] Final record count is: 174931
```

> Record count is determined by the `au_trailer32_t` field in the audit trail upon which the count will be incremented by 1.

# Contribute

If you spot a bug, typo or want to contribute feel free to shoot in a pull request or issue :)

# Credits

This project would not be have possible without the help of the following individual(s):

- [MrYoranimo](https://github.com/MrYoranimo)
