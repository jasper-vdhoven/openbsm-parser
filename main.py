#!/usr/bin/env python
from sys import argv, exit
from dissect import cstruct
from dissect.cstruct import dumpstruct

cdef = """

/*
 * https://github.com/openbsm/openbsm/blob/54a0c07cf8bac71554130e8f6760ca68e5f36c7f/sys/bsm/audit_record.h#L41
 */

/*
 * Token type identifiers.
 */
#define	AUT_INVALID		0x00
#define	AUT_TRAILER		0x13
#define	AUT_HEADER32		0x14
#define	AUT_RETURN32		0x27
#define	AUT_TEXT		0x28


/*
 * Structs pulled from https://github.com/openbsm/openbsm/blob/54a0c07cf8bac71554130e8f6760ca68e5f36c7f/bsm/libbsm.h
 * Types changed from u_int8_t / u_int16_t / u_int32_t -> uint8_t / uint16_t / uint32_t / etc to match types with Dissect.cstruct
 */

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

/*
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
	uint16_t	 len;
	char		*text;
} au_text_t;

/*
 * error status            1 byte
 * return value            4 bytes/8 bytes (32-bit/64-bit value)
 */
typedef struct {
	uchar		status;
	uint32_t	ret;
} au_ret32_t;

/*
 * trailer magic number    2 bytes
 * record byte count       4 bytes
 */
typedef struct {
	uint16_t	magic;
	uint32_t	count;
} au_trailer_t;
"""

def main():
    cs = cstruct.cstruct
    aurecord = cs(endian='>')
    aurecord.load(cdef, compiled=True)

    if len(argv) != 2:
        exit("usage: main.py <audit_trail>")

    try:
        fh = open(argv[1], 'rb')
    except FileNotFoundError:
        raise

    # Check the first byte for record type
    header_type = fh.read(1)

    match header_type:
        case b'\x14':
            print("Type is AU_HEADER32")
            au_header32_t = aurecord.au_header32_t(fh)
            dumpstruct(au_header32_t)
        case _:
            print("invalid record type %s" % header_type)

    record_item = fh.read(1)

    match record_item:
        case b'\x28':
            print("\nType is AU_TEXT")
            record_length = int.from_bytes(fh.read(2), "big")
            print("len: %s" % int(record_length))

            record_text = fh.read(record_length)
            print("record text: %s" % record_text.decode("utf-8"))
        case _:
            print("invalid record type %s" % record_item)

    record_item2 = fh.read(1)

    match record_item2:
        case b'\x27':
            print("\nType is AU_RETURN32")
            au_ret32 = aurecord.au_ret32_t(fh)
            dumpstruct(au_ret32)
        case _:
            print("invalid record type %s" % record_item2)

    record_item3 = fh.read(1)

    match record_item3:
        case b'\x13':
            print("\nType is AU_TRAILER_T")
            au_trailer_t = aurecord.au_trailer_t(fh)
            dumpstruct(au_trailer_t)
        case _:
            print("invalid record type %s" % record_item3)

if __name__ == '__main__':
    main()

