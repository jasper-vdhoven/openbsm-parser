#!/usr/bin/env python
from sys import argv, exit
from dissect.cstruct import cstruct, dumpstruct
import logging
import xml.etree.cElementTree as ET

# Set logging info
logging.basicConfig(level=logging.INFO)
logging.basicConfig(format='[D] - %(asctime)s - %(message)s', level=logging.DEBUG)
logging.basicConfig(format='[I] - %(asctime)s - %(message)s', level=logging.INFO)
logging.basicConfig(format='[E] - %(asctime)s - %(message)s', level=logging.WARN)
logging.basicConfig(format='[E] - %(asctime)s - %(message)s', level=logging.CRITICAL)


cdef = """
/*
 * Structs pulled from https://github.com/openbsm/openbsm/blob/54a0c07cf8bac71554130e8f6760ca68e5f36c7f/bsm/libbsm.h
 * Types changed from u_int8_t / u_int16_t / u_int32_t -> uint8_t / uint16_t / uint32_t / etc to match types with Dissect.cstruct
 */

typedef struct au_tid32 {
	uint32_t	port;
	uint32_t	addr;
} au_tid32_t;

typedef struct au_tid64 {
	uint64_t	port;
	uint32_t	addr;
} au_tid64_t;

typedef struct au_tidaddr32 {
	uint32_t	port;
	uint32_t	type;
	uint32_t	addr[type / 4];
} au_tidaddr32_t;

typedef struct au_tidaddr64 {
	uint64_t	port;
	uint32_t	type;
	uint32_t	addr[4];
} au_tidaddr64_t;

/*
 * argument #              1 byte
 * argument value          4 bytes/8 bytes (32-bit/64-bit value)
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
	uchar		 no;
	uint32_t	 val;
	uint16_t	 len;
	// changed type char *text to play nice with Dissect parsing
    char         text[len-1];
    char         nbt;
} au_arg32_t;

typedef struct {
	uchar		 no;
	uint64_t	 val;
	uint16_t	 len;
	// changed type char *text to play nice with Dissect parsing
    char         text[len-1];
    char         nbt;
} au_arg64_t;

/*
 * token ID                1 byte
 * argument #              1 byte
 * uuid                    16 bytes
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
	uchar		no;
	uint8_t	uuid[16];
	uint16_t	len;
	char		*text;
} au_arg_uuid_t;

/*
 * how to print            1 byte
 * basic unit              1 byte
 * unit count              1 byte
 * data items              (depends on basic unit)
 */
typedef struct {
	uchar	 howtopr;
	uchar	 bu;
	uchar	 uc;
	uchar	*data;
} au_arb_t;

/*
 * file access mode        4 bytes
 * owner user ID           4 bytes
 * owner group ID          4 bytes
 * file system ID          4 bytes
 * node ID                 8 bytes
 * device                  4 bytes/8 bytes (32-bit/64-bit)
 */
typedef struct {
	uint32_t	mode;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	fsid;
	uint64_t	nid;
	uint32_t	dev;
} au_attr32_t;

typedef struct {
	uint32_t	mode;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	fsid;
	uint64_t	nid;
	uint64_t	dev;
} au_attr64_t;

/*
 * count                   4 bytes
 * text                    count null-terminated string(s)
 */
typedef struct {
	uint32_t	 count;
    // type is changed from char *text[AUDIT_MAX_ARGS]; to play nice with Dissect parsing
	char		text[count][];
} au_execarg_t;

/*
 * count                   4 bytes
 * text                    count null-terminated string(s)
 */
typedef struct {
	uint32_t	 count;
    // type is changed from char *text[AUDIT_MAX_ENV]; to play nice with Dissect parsing
	char		text[count][];
} au_execenv_t;

/*
 * status                  4 bytes
 * return value            4 bytes
 */
typedef struct {
	uint32_t	status;
	uint32_t	ret;
} au_exit_t;

/*
 * seconds of time         4 bytes
 * milliseconds of time    4 bytes
 * file name length        2 bytes
 * file pathname           N bytes + 1 terminating NULL byte
 */
typedef struct {
	uint32_t	 s;
	uint32_t	 ms;
	uint16_t	 len;
	char		*name;
} au_file_t;


/*
 * number groups           2 bytes
 * group list              N * 4 bytes
 */
typedef struct {
	uint16_t	no;
    // type is changed from u_int32_t list[AUDIT_MAX_GROUPS] to play nice with Dissect parsing
	uint32_t	list[no][];
} au_groups_t;

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
 * record byte count       4 bytes
 * version #               1 byte     [2]
 * event type              2 bytes
 * event modifier          2 bytes
 * address type/length     1 byte (XXX: actually, 4 bytes)
 * machine address         4 bytes/16 bytes (IPv4/IPv6 address)
 * seconds of time         4 bytes/8 bytes  (32/64-bits)
 * nanoseconds of time     4 bytes/8 bytes  (32/64-bits)
 */
typedef struct {
	uint32_t	size;
	uchar		version;
	uint16_t	e_type;
	uint16_t	e_mod;
	uint32_t	ad_type;
	uint32_t	addr[4];
	uint32_t	s;
	uint32_t	ms;
} au_header32_ex_t;

typedef struct {
	uint32_t	size;
	uchar		version;
	uint16_t	e_type;
	uint16_t	e_mod;
	uint64_t	s;
	uint64_t	ms;
} au_header64_t;

typedef struct {
	uint32_t	size;
	uchar		version;
	uint16_t	e_type;
	uint16_t	e_mod;
	uint32_t	ad_type;
	uint32_t	addr[4];
	uint64_t	s;
	uint64_t	ms;
} au_header64_ex_t;

/*
 * internet address        4 bytes
 */
typedef struct {
	uint32_t	addr;
} auinaddr_t;

/*
 * type                 4 bytes
 * internet address     16 bytes
 */
typedef struct {
	uint32_t	type;
	uint32_t	addr[4];
} auinaddr_ex_t;

/*
 * version and ihl         1 byte
 * type of service         1 byte
 * length                  2 bytes
 * id                      2 bytes
 * offset                  2 bytes
 * ttl                     1 byte
 * protocol                1 byte
 * checksum                2 bytes
 * source address          4 bytes
 * destination address     4 bytes
 */
typedef struct {
	uchar		version;
	uchar		tos;
	uint16_t	len;
	uint16_t	id;
	uint16_t	offset;
	uchar		ttl;
	uchar		prot;
	uint16_t	chksm;
	uint32_t	src;
	uint32_t	dest;
} auip_t;

/*
 * object ID type          1 byte
 * object ID               4 bytes
 */
typedef struct {
	uchar		type;
	uint32_t	id;
} auipc_t;

/*
 * owner user ID           4 bytes
 * owner group ID          4 bytes
 * creator user ID         4 bytes
 * creator group ID        4 bytes
 * access mode             4 bytes
 * slot sequence #         4 bytes
 * key                     4 bytes
 */
typedef struct {
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	puid;
	uint32_t	pgid;
	uint32_t	mode;
	uint32_t	seq;
	uint32_t	key;
} auipcperm_t;

/*
 * port IP address         2 bytes
 */
typedef struct {
	uint16_t	port;
} auiport_t;

/*
 * length		2 bytes
 * data			length bytes
 */
typedef struct {
	uint16_t	 size;
	// changed type from char *data to play nice with Dissect parsing
    char         data[size-1];
    char         nbt;
} au_opaque_t;

/*
 * path length             2 bytes
 * path                    N bytes + 1 terminating NULL byte
 */
typedef struct {
	uint16_t	 len;
	// changed type char *path to play nice with Dissect parsing
    char         path[len-1];
    char         nbt;
} au_path_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * machine address       4 bytes
 */
typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	// commented out to aid printing struct au_tid32_t tid;
    uint32_t	tid_port;
	uint32_t	tid_addr;
} au_proc32_t;

typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	// commented out to aid printing struct au_tid64_t tid;
    uint64_t	tid_port;
	uint32_t	tid_addr;
} au_proc64_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * type                  4 bytes
 * machine address       16 bytes
 */
typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	au_tidaddr32_t	tid;
} au_proc32ex_t;

typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	au_tidaddr64_t	tid;
} au_proc64ex_t;

/*
 * error status            1 byte
 * return value            4 bytes/8 bytes (32-bit/64-bit value)
 */
typedef struct {
	uchar		status;
	uint32_t	ret;
} au_ret32_t;

typedef struct {
	uchar		err;
	uint64_t	val;
} au_ret64_t;

/*
 * token ID                1 byte
 * return value #          1 byte
 * uuid                    16 bytes
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
	uchar		 no;
	uint8_t	 uuid[16];
	uint16_t	 len;
	char		*text;
} au_ret_uuid_t;

/*
 * sequence number         4 bytes
 */
typedef struct {
	uint32_t	seqno;
} au_seq_t;

/*
 * socket type             2 bytes
 * local port              2 bytes
 * local Internet address  4 bytes
 * remote port             2 bytes
 * remote Internet address 4 bytes
 */
typedef struct {
	uint16_t	type;
	uint16_t	l_port;
	uint32_t	l_addr;
	uint16_t	r_port;
	uint32_t	r_addr;
} au_socket_t;

// OpenBSM source code lists wrong comment
// struct def taken from: https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/security/audit/audit_bsm_token.c#L803
/*
 * socket domain	2 bytes
 * socket type		2 bytes
 * address type		2 bytes
 * local port		2 bytes
 * local address	4 bytes/16 bytes (IPv4/IPv6 address)
 * remote port		2 bytes
 * remote address	4 bytes/16 bytes (IPv4/IPv6 address)
 */
typedef struct {
	uint16_t	domain;
	uint16_t	type;
	uint16_t	atype;
	uint16_t	l_port;
    // dynamically calculate the space required; thx Yoran for the Wolfram magic
	uint8_t	    l_addr[(6 * atype) - 20];
	uint16_t	r_port;
	uint8_t	    r_addr[(6 * atype) - 20];
} au_socket_ex32_t;

/*
 * socket family           2 bytes
 * local port              2 bytes
 * socket address          4 bytes/16 bytes (IPv4/IPv6 address)
 */
typedef struct {
	uint16_t	family;
	uint16_t	port;
	uint32_t	addr[4];
} au_socketinet_ex32_t;

typedef struct {
	uint16_t	family;
	uint16_t	port;
	uint32_t	addr;
} au_socketinet32_t;

/*
 * socket family           2 bytes
 * path                    104 bytes
 */
typedef struct {
	uint16_t	family;
	char		path[104];
} au_socketunix_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * 	port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * 	machine address       4 bytes
 */
typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	// commented out to aid displaying struct au_tid32_t tid;
    uint32_t	tid_port;
	uint32_t	tid_addr;
} au_subject32_t;

typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	// commented out to aid printing struct au_tid64_t tid;
    uint64_t	tid_port;
	uint32_t	tid_addr;
} au_subject64_t;

/*
 * audit ID                4 bytes
 * effective user ID       4 bytes
 * effective group ID      4 bytes
 * real user ID            4 bytes
 * real group ID           4 bytes
 * process ID              4 bytes
 * session ID              4 bytes
 * terminal ID
 * port ID               4 bytes/8 bytes (32-bit/64-bit value)
 * type                  4 bytes
 * machine address       16 bytes
 */
typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	// commented out to aid printing struct au_tidaddr32_t tid;
    uint32_t	port;
    uint32_t	type;
    uint32_t	addr[type / 4];
} au_subject32ex_t;

typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	// commented out to aid printing struct au_tidaddr64_t tid;
	uint64_t	port;
	uint32_t	type;
	uint32_t	addr[4];
} au_subject64ex_t;

/*
 * text length             2 bytes
 * text                    N bytes + 1 terminating NULL byte
 */
typedef struct {
	uint16_t	 len;
    // changed type from char *text to play nice with dissect parsing
	char		 text[len-1];
    char         nbt;
} au_text_t;

/*
 * upriv status         1 byte
 * privstr len          2 bytes
 * privstr              N bytes + 1 (\0 byte)
 */
typedef struct {
	uint8_t	 sorf;
	uint16_t	 privstrlen;
	// changed type char *priv to play nice with Dissect parsing
    char         priv[privstrlen-1];
    char         nbt;
} au_priv_t;

/*
* privset
* privtstrlen		2 bytes
* privtstr		N Bytes + 1
* privstrlen		2 bytes
* privstr		N Bytes + 1
*/
typedef struct {
	uint16_t	 privtstrlen;
	char		*privtstr;
	uint16_t	 privstrlen;
	char		*privstr;
} au_privset_t;

/*
 * zonename length	2 bytes
 * zonename text	N bytes + 1 NULL terminator
 */
typedef struct {
	uint16_t	 len;
	// changed type char *zonename to play nice with Dissect parsing
    char         zonename[len-1];
    char         nbt;
} au_zonename_t;

typedef struct {
	uint32_t	ident;
	uint16_t	filter;
	uint16_t	flags;
	uint32_t	fflags;
	uint32_t	data;
} au_kevent_t;

typedef struct {
	uint16_t	 length;
	// changed type char *data to play nice with Dissect parsing
    char         data[length-1];
    char         nbt;
} auinvalid_t;

/*
 * trailer magic number    2 bytes
 * record byte count       4 bytes
 */
typedef struct {
	uint16_t	magic;
	uint32_t	count;
} au_trailer_t;

// special struct that is used to parse local Unix sockets
// struct matches AUT_SOCKET // 0x82
typedef struct {
    ushort      family;
    char        addr[];
} au_unixsock_t_special;
"""

# TODO: run a macOS / Solaris audit trail through the current parser and see how it holds up

def print_items(parsed_record):
    # Get the individual items inside each audit token, similar to how dissect's dumpstruct does
    for item in parsed_record._type.fields:
        value = getattr(parsed_record, item.name)
        print("- %s: %s" % (item.name, value))


def main():
    aurecord = cstruct(endian=">")
    aurecord.load(cdef, compiled=True)

    # XML doc definitions
    audit = ET.Element("audit")

    if len(argv) != 2:
        exit("usage: main.py <audit_trail>")

    try:
        logging.info(f'Attempting to open file: {argv[1]}')
        fh = open(argv[1], "rb")
    except FileNotFoundError:
        logging.warning(f"Could not open file: {argv[1]}")
        raise FileNotFoundError

    not_empty = True
    clean = True

    while not_empty and clean:
        # Check the first byte for record type
        logging.info("Reading one byte to determine record type")
        header_type = fh.read(1)
        logging.debug(f"Byte read is: {header_type}")

        match header_type:
            case b"\x00":
                token_type = "AUINVALID_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auinvalid_t = aurecord.auinvalid_t(fh)
            case b"\x13":
                token_type = "AU_TRAILER_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_trailer_t = aurecord.au_trailer_t(fh)
                logging.info(f"Record end reached; returning for next record")
            case b"\x14":
                token_type = "AU_HEADER32_T"
                logging.info("Record start; parsing record contents")
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_header32_t = aurecord.au_header32_t(fh)

                logging.debug(f"Adding parsed record to XML object")
                record = ET.SubElement(
                    audit,
                    "record",
                    version=str(au_header32_t.version),
                    event=str(au_header32_t.e_type),
                    modifier=str(au_header32_t.e_mod),
                    time=str(au_header32_t.s),
                    msec=f" + {str(au_header32_t.ms)} msec",
                )
            case b"\x15":
                token_type = "AU_HEADER32_EX_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_header32_ex_t = aurecord.au_header32_ex_t(fh)

                au_data_t = aurecord.au_idkdata_t(fh)
                dumpstruct(au_data_t)
            case b"\x22":
                token_type = "AUIPC_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auipc_t = aurecord.auipc_t(fh)
            case b"\x23":
                token_type = "AU_PATH_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_path_t = aurecord.au_path_t(fh)
                logging.debug(f"Adding parsed record to XML object")
                au_path = ET.SubElement(record, "path")
                au_path.text = au_path_t.path.decode("utf-8")
            case b"\x24":
                token_type = "AU_SUBJECT32_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_subject32_t = aurecord.au_subject32_t(fh)

                logging.debug(f"Adding parsed record to XML object")
                ET.SubElement(
                    record,
                    "subject",
                    audit_id=str(au_subject32_t.auid),
                    uid=str(au_subject32_t.euid),
                    gid=str(au_subject32_t.egid),
                    ruid=str(au_subject32_t.ruid),
                    rgid=str(au_subject32_t.rgid),
                    pid=str(au_subject32_t.pid),
                    sid=str(au_subject32_t.sid),
                    tid=(au_subject32_t.tid_port, au_subject32_t.tid_addr),
                )
            case b"\x26":
                token_type = "AU_PROC32_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_proc32_t = aurecord.au_proc32_t(fh)
            case b"\x27":
                token_type = "AU_RET32_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_ret32_t = aurecord.au_ret32_t(fh)

                logging.debug(f"Adding parsed record to XML object")
                ET.SubElement(
                    record,
                    "return",
                    errval=str(au_ret32_t.status),
                    retval=str(au_ret32_t.ret),
                )
            case b"\x28":
                token_type = "AU_TEXT_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_text_t = aurecord.au_text_t(fh)

                au_text = ET.SubElement(record, "text")
                au_text.text = au_text_t.text.decode("utf-8")
            case b"\x29":
                token_type = "AU_OPAQUE_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_opaque_t = aurecord.au_opaque_t(fh)
            case b"\x2a":
                token_type = "AUINADDR_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auinaddr_t = aurecord.auinaddr_t(fh)
            case b"\x2b":
                token_type = "AUIP_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auip_t = aurecord.auip_t(fh)
            case b"\x2c":
                token_type = "AUIPORT_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auiport_t = aurecord.auiport_t(fh)
            case b"\x2d":
                token_type = "AU_ARG32_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_arg32_t = aurecord.au_arg32_t(fh)

                logging.debug(f"Adding parsed record to XML object")
                ET.SubElement(
                    record,
                    "argument",
                    arg_num=str(au_arg32_t.no),
                    value=str(au_arg32_t.val),
                    desc=str(au_arg32_t.text.decode("utf-8")),
                )
            case b"\x2e":
                token_type = "AU_SOCKET_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_socket_t = aurecord.au_socket_t(fh)
            case b"\x2f":
                token_type = "AU_SEQ_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_seq_t = aurecord.au_seq_t(fh)
            case b"\x31":
                token_type = "AU_ATTR_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_attr_t = aurecord.au_attr_t(fh)
            case b"\x32":
                token_type = "AUIPCPERM_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auipcperm_t = aurecord.auipcperm_t(fh)
            case b"\x34":
                token_type = "AU_PRIV_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_groups_t = aurecord.au_groups_t(fh)
            case b"\x38":
                token_type = "AU_PRIV_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_priv_t = aurecord.au_priv_t(fh)
            case b"\x3c":
                token_type = "AU_EXECARG_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_execarg_t = aurecord.au_execarg_t(fh)

                au_execarg = ET.SubElement(record, "exec_args")
                for items in au_execarg_t.text:
                    arg = ET.SubElement(au_execarg, "arg")
                    arg.text = items.decode("utf-8")
            case b"\x3d":
                token_type = "AU_EXECENV_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_execenv_t = aurecord.au_execenv_t(fh)

                au_execenv = ET.SubElement(record, "exec_env")
                for items in au_execenv_t.text:
                    arg = ET.SubElement(au_execenv, "env")
                    arg.text = items.decode("utf-8")
            case b"\x3e":
                token_type = "AU_ATTR32_t"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_attr32_t = aurecord.au_attr32_t(fh)

                logging.debug(f"Adding parsed record to XML object")
                ET.SubElement(
                    record,
                    "attribute",
                    mode=str(au_attr32_t.mode),
                    uid=str(au_attr32_t.uid),
                    gid=str(au_attr32_t.gid),
                    fsid=str(au_attr32_t.fsid),
                    nodeid=str(au_attr32_t.nid),
                    device=str(au_attr32_t.dev),
                )
            case b"\x52":
                token_type = "AU_EXIT_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_exit_t = aurecord.au_exit_t(fh)
            case b"\x60":
                token_type = "AU_ZONENAME_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_zonename_t = aurecord.au_zonename_t(fh)
            case b"\x71":
                token_type = "AU_ARG64_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_arg64_t = aurecord.au_arg64_t(fh)

                ET.SubElement(
                    record, "argument",
                    arg_num=str(au_arg64_t.no),
                    value=hex(au_arg64_t.val),
                    desc=(au_arg64_t.text.decode("utf-8"))
                )
            case b"\x72":
                token_type = "AU_RET64_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_ret64_t = aurecord.au_ret64_t(fh)
            case b"\x73":
                token_type = "AU_ATTR64_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_attr64_t = aurecord.au_attr64_t(fh)
            case b"\x74":
                token_type = "AU_HEADER64_t"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_header64_t = aurecord.au_header64_t(fh)
            case b"\x75":
                token_type = "AU_SUBJECT64_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_subject64_t = aurecord.au_subject64_t(fh)
            case b"\x77":
                token_type = "AU_PROCESS64_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_proc64_t = aurecord.au_proc64_t(fh)
            case b"\x79":
                token_type = "AU_HEADER64_EX_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_header64_ex_t = aurecord.au_header64_ex_t(fh)
            case b"\x7a":
                token_type = "AU_SUBJECT32EX_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_subject32ex_t = aurecord.au_subject32ex_t(fh)
            case b"\x7b":
                token_type = "AU_PROC32EXT_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_proc32ex_t = aurecord.au_proc32ex_t(fh)
            case b"\x7c":
                token_type = "AU_SUBJECT64EX_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_subject64ex_t = aurecord.au_subject64ex_t(fh)
            case b"\x7d":
                token_type = "AU_PROC64EX_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_proc64ex_t = aurecord.au_proc64ex_t(fh)
            case b"\x7e":
                token_type = "AUINADDR_EX_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                auinaddr_ex_t = aurecord.auinaddr_ex_t(fh)
                logging.info(print_items(auinaddr_ex_t))
            case b"\x7f":
                token_type = "AU_SOCKET_EX32_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_socket_ex32_t = aurecord.au_socket_ex32_t(fh)
                ET.SubElement(
                    record, "socket",
                    sock_dom=hex(au_socket_ex32_t.domain),
                    atype=str(au_socket_ex32_t.atype),
                    sock_type=hex(au_socket_ex32_t.type),
                    lport=str(au_socket_ex32_t.l_port),
                    laddr=str(au_socket_ex32_t.l_addr),
                    faddr=str(au_socket_ex32_t.r_addr),
                    fport=str(au_socket_ex32_t.r_port)
                )
            case b"\x80":
                token_type = "AU_SOCKETINET32_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_socketinet32_t = aurecord.au_socketinet32_t(fh)

                ET.SubElement(
                    record, "socket_inet",
                    type=str(au_socketinet32_t.family),
                    port=str(au_socketinet32_t.port),
                    addr=str(au_socketinet32_t.addr)
                )
            case b"\x81":
                token_type = "AU_SOCKETINET128_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")

                au_socketinet128_t = aurecord.au_socketinet128_t(fh)

                ET.SubElement(
                    record, "socket_inet6",
                    type=str(au_socketinet128_t.socket_family),
                    port=str(au_socketinet128_t.l_port),
                    addr=str(au_socketinet128_t.addr)
                )
            case b"\x82":
                token_type = "AU_UNIXSOCKET_T"
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")
                au_unixsocket_t_special = aurecord.au_unixsock_t_special(fh)

                logging.debug(f"Adding parsed record to XML object")
                ET.SubElement(
                    record,
                    "socket-unix",
                    type=str(au_unixsocket_t_special.family),
                    port="",
                    addr=str(au_unixsocket_t_special.addr.decode("utf-8")),
                )
            case b"\xed":
                token_type = "AUT_IDENTITY_INFO 0xED"
                logging.info("macOS specific record encountered")
                logging.info(f"Type is: {header_type} aka {token_type}")
                logging.debug(f"Parsing memory for type: {token_type}")

                au_identity_info = aurecord.au_identity_info(fh)
                logging.debug("Adding parsed record to XML object")

                ET.SubElement(
                    record, "identity",
                    signer_type=str(au_identity_info.signer_type),
                    signing_id=(au_identity_info.signing_id.decode("utf-8")),
                    signing_id_truncated=str(au_identity_info.signing_id_trunc),
                    team_id=(au_identity_info.team_id.decode("utf-8")),
                    team_id_truncated=str(au_identity_info.team_id_trunc),
                    cdhash=(au_identity_info.cdhash.hex())
                )
            case b"":
                logging.info("End of file reached; no errors occurred getting here")
                logging.info("Exiting loop on clean state & writing collected XML to disk")
                not_empty = False
            case _:
                logging.error(f"Encountered invalid record byte: {header_type}; this might be because it is not (yet) supported or a bug!")
                logging.error(f"Writing collected XML to disk; then exiting on non-zero exit code")
                clean = False

    logging.debug("Attempting to open XML output file: xml-dump.xml")
    with open("xml-dump.xml", "w+") as f:
        logging.debug("Writing XML version information to disk")
        f.write("<?xml version='1.0'?>")
        logging.info("Writing collected XML to disk")
        f.write(ET.tostring(audit, method="xml").decode("utf-8"))
        logging.info("Wrote collected XML to disk")
        if not clean:
            logging.critical("XMl is not completed due to prior error!")
            logging.critical("Check logs and output for possible reasons for premature exit")
            exit -1
    logging.info("Exiting on exit code 0; all good to go!")


if __name__ == "__main__":
    main()
