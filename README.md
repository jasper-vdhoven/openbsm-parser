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
[+] Type is AU_HEADER32_T
- size: 97
- version: 11
- e_type: 6159
- e_mod: 0
- s: 1637060334
- ms: 419
```

## Future update plans

At the time of writing, this parser should be able to parse ~~all~~ records that OpenBSM contains among those that I was able to easily get testing data for. The goal is to have the parser output its results as XML so that they can then be easily ingested into Splunk, Elastic, et al and be used in digital forensic investigations.

If you spot a bug, typo or want to contribute feel free to shoot in a pull request or issue :)