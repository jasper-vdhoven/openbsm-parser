#!/usr/bin/env python
from sys import argv, exit
from dissect.cstruct import cstruct, dumpstruct

#TODO: Figure out what to do with these
class Text_record:
    def __init__(self, type:str, len: int, text):
        self.type:str = type
        self.len = len
        self.text = text

    def __repr__(self):
        return f"<{self.type} len={self.len}, text={self.text}>"


class Arg_record:
    def __init__(self,type:str, no, val:int, len:int, text):
        self.type = type
        self.no = no
        self.val = val
        self.len = len
        self.text = text
    
    def __repr__(self) -> str:
        return f"<{self.type} no={self.no}, val={self.val}, len={self.len}, text={self.text}>"

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

/*
 * socket type             2 bytes
 * local port              2 bytes
 * address type/length     4 bytes
 * local Internet address  4 bytes/16 bytes (IPv4/IPv6 address)
 * remote port             4 bytes
 * address type/length     4 bytes
 * remote Internet address 4 bytes/16 bytes (IPv4/IPv6 address)
 */
typedef struct {
	uint16_t	domain;
	uint16_t	type;
	uint16_t	atype;
	uint16_t	l_port;
	uint32_t	l_addr[4];
	uint32_t	r_port;
	uint32_t	r_addr[4];
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
	au_tidaddr32_t	tid;
} au_subject32ex_t;

typedef struct {
	uint32_t	auid;
	uint32_t	euid;
	uint32_t	egid;
	uint32_t	ruid;
	uint32_t	rgid;
	uint32_t	pid;
	uint32_t	sid;
	au_tidaddr64_t	tid;
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
	// changed type char *zonename to play nice witd Dissect parsing
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
"""

def print_items(parsed_record):
    # Get the individual items inside each audit token, similar to how dissect's dumpstruct does
    for item in parsed_record._type.fields:
        value = getattr(parsed_record, item.name)
        print("- %s: %s" % (item.name, value))

def main():
    aurecord = cstruct(endian='>')
    aurecord.load(cdef, compiled=True)

    if len(argv) != 2:
        exit("usage: main.py <audit_trail>")

    try:
        fh = open(argv[1], 'rb')
    except FileNotFoundError:
        raise

    not_empty = True

    while not_empty:
        # Check the first byte for record type
        header_type = fh.read(1)

        match header_type:
            case b'\x00':
                token_type = "AU_INVALID_T"
                print("\n[+] Type is %s" % token_type)
                record_auinvalid_t_len = int.from_bytes(fh.read(2), "big")
                record_auinvalid_t_text = fh.read(record_auinvalid_t_len)
                record_class = Text_record(
                    token_type.lower(), record_auinvalid_t_len, record_auinvalid_t_text)
                print("len: %s \ntext: %s" % (record_auinvalid_t_len,
                                              record_auinvalid_t_text.decode("utf-8")))
            case b'\x13':
                token_type = "AU_TRAILER_T"
                print("\n[+] Type is %s" % token_type)
                au_trailer_t = aurecord.au_trailer_t(fh)
                print_items(au_trailer_t)
                # dumpstruct(au_trailer_t)
                print("="*21 + "END AUDIT RECORD" + "="*21)
            case b'\x14':
                token_type = "AU_HEADER32_T"
                print("="*20 + "START AUDIT RECORD" + "="*20)
                print("\n[+] Type is %s" % token_type)
                au_header32_t = aurecord.au_header32_t(fh)
                print_items(au_header32_t)
                # dumpstruct(au_header32_t)
            case b'\x15':
                token_type = "AU_HEADER32_EX_T"
                print("\n[+] Type is %s" % token_type)
                au_header32_ex_t = aurecord.au_header32_ex_t(fh)
                print_items(au_header32_ex_t)
                # dumpstruct(au_header32_ex_t)
            case b'\x22':
                token_type = "AUIPC_T"
                print("\n[+] Type is %s" % token_type)
                auipc_t = aurecord.auipc_t(fh)
                print_items(auipc_t)
                # dumpstruct(auipc_t)
            case b'\x23':
                token_type = "AU_PATH_T"
                print("\n[+] Type is %s" % token_type)
                record_aupath_t_len = int.from_bytes(fh.read(2), "big")
                record_aupath_t_text = fh.read(record_aupath_t_len)
                record_class = Text_record(
                    token_type.lower(), record_aupath_t_len, record_aupath_t_text)
                print("len: %s \ntext: %s\ndecoded: %s" % (
                    record_aupath_t_len, record_aupath_t_text, record_aupath_t_text.decode("utf-8")))
            case b'\x24':
                token_type = "AU_SUBJECT32_T"
                print("\n[+] Type is %s" % token_type)
                au_subject32_t = aurecord.au_subject32_t(fh)
                print_items(au_subject32_t)
                # dumpstruct(au_subject32_t)
            case b'\x26':
                token_type = "AU_PROC32_T"
                print("\n[+] Type is %s" % token_type)
                au_proc32_t = aurecord.au_proc32_t(fh)
                print_items(au_proc32_t)
                # dumpstruct(au_proc32_t)
            case b'\x27':
                token_type = "AU_RET32_T"
                print("\n[+] Type is %s" % token_type)
                au_ret32_t = aurecord.au_ret32_t(fh)
                print_items(au_ret32_t)
                # dumpstruct(au_ret32)
            case b'\x28':
                token_type = "AU_TEXT_T"
                print("\n[+] Type is %s" % token_type)
                record_autext_t_len = int.from_bytes(fh.read(2), "big")
                record_autext_t_text = fh.read(record_autext_t_len)
                record_class = Text_record(
                    token_type.lower(), record_autext_t_len, record_autext_t_text)
                print("- len: %s\n- text: %s" %
                      (record_autext_t_len, record_autext_t_text.decode("utf-8")))
            case b'\x29':
                token_type = "AU_OPAQUE_T"
                print("\n[+] Type is %s" % token_type)
                record_auopaque_t_len = int.from_bytes(fh.read(2), "big")
                record_auopaque_t_text = fh.read(record_auopaque_t_len)
                print("len: %s \ntext: %s" % (record_auopaque_t_len,
                                              record_auopaque_t_text.decode("utf-8")))
            case b'\x2a':
                token_type = "AUINADDR_T"
                print("\n[+] Type is %s" % token_type)
                auinaddr_t = aurecord.auinaddr_t(fh)
                print_items(auinaddr_t)
                # dumpstruct(auinaddr_t)
            case b'\x2b':
                token_type = "AUIP_T"
                print("\n[+] Type is %s" % token_type)
                auip_t = aurecord.auip_t(fh)
                print_items(auip_t)
                # dumpstruct(auip_t)
            case b'\x2c':
                token_type = "AUIPORT_T"
                print("\n[+] Type is %s" % token_type)
                auiport_t = aurecord.auiport_t(fh)
                print_items(auiport_t)
                # dumpstruct(auiport_t)
            case b'\x2d':
                token_type = "AU_ARG32_T"
                print("\n[+] Type is %s" % token_type)
                record_auarg32t_no = fh.read(1)
                record_auarg32t_val = int.from_bytes(fh.read(4), "big")
                record_auarg32t_len = int.from_bytes(fh.read(2), "big")
                record_auarg32t_text = fh.read(record_auarg32t_len)
                record_class = Arg_record(token_type.lower(),record_auarg32t_no,record_auarg32t_val,record_auarg32t_len,record_auarg32t_text)
                print("- no: %s\n- val: %s\n- len: %s\n- text: %s" % (record_auarg32t_no,
                      record_auarg32t_val, record_auarg32t_len, record_auarg32t_text))
            case b'\x2e':
                token_type = "AU_SOCKET_T"
                print("\n[+] Type is %s" % token_type)
                au_socket_t = aurecord.au_socket_t(fh)
                print_items(au_socket_t)
                # dumpstruct(au_socket_t)
            case b'\x2f':
                token_type = "AU_SEQ_T"
                print("\n[+] Type is %s" % token_type)
                au_seq_t = aurecord.au_seq_t(fh)
                print_items(au_seq_t)
                # dumpstruct(au_seq_t)
            case b'\x31':
                token_type = "AU_ATTR_T"
                print("\n[+] Type is %s" % token_type)
                au_attr_t = aurecord.au_attr_t(fh)
                print_items(au_attr_t)
                # dumpstruct(au_attr_t)
            case b'\x32':
                token_type = "AUIPCPERM_T"
                print("\n[+] Type is %s")
                auipcperm_t = aurecord.auipcperm_t(fh)
                print_items(auipcperm_t)
                # dumpstruct(auipcperm_t)
            case b'\x34':
                token_type = "AU_PRIV_T"
                print("\n[+] Type is %s" % token_type)
                au_groups_t = aurecord.au_groups_t(fh)
                print_items(au_groups_t)
                # dumpstruct(au_groups_t)
            case b'\x38':
                token_type = "AU_PRIV_T"
                print("\n[+] Type is: %s")
                record_auprivt_sorf = int.from_bytes(fh.read(1), "big")
                record_auprivt_privstrlen = int.from_bytes(fh.read(2), "big")
                record_auprivt_priv = fh.read(record_auprivt_privstrlen)
                print("sorf: %s\nprivstrlen: %s\npriv: %s" % (
                    record_auprivt_sorf, record_auprivt_privstrlen, record_auprivt_priv))
            case b'\x3c':
                token_type = "AU_EXECARG_T"
                # dirty hack, because cstruct does not support an array of null-terminated
                # strings (yet)
                print("\n[+] Type is: %s")

                au_execarg_t_count = int.from_bytes(fh.read(4), "big")
                au_execarg_t_text = read_nts_array(fh, au_execarg_t_count)

                print("- count: {}".format(au_execarg_t_count))
                print("- text[]:")
                print("\n".join(["  - " + x for x in au_execarg_t_text]))
            case b'\x3d':
                token_type = "AU_EXECENV_T"
                print("\n[+] Type is %s" % token_type)

                au_execenv_t_count = int.from_bytes(fh.read(4), "big")
                au_execenv_t_text = read_nts_array(fh, au_execenv_t_count)

                print("- count: {}".format(au_execenv_t_count))
                print("- text[]:")
                print("\n".join(["  - " + x for x in au_execenv_t_text]))
            case b'\x3e':
                token_type = "AU_ATTR32_t"
                print("\n[+] Type is %s" % token_type)
                au_attr32_t = aurecord.au_attr32_t(fh)
                print_items(au_attr32_t)
                # dumpstruct(au_attr32_t)
            case b'\x52':
                token_type = "AU_EXIT_T"
                print("\n[+] Type is %s" % token_type)
                au_exit_t = aurecord.au_exit_t(fh)
                print_items(au_exit_t)
                # dumpstruct(au_exit_t)
            case b'\x60':
                token_type = "AU_ZONENAME_T"
                print("\n[+] Type is %s" % token_type)
                record_auzonenamet_len = int.from_bytes(fh.read(2), "big")
                record_auzonenamet_zonename = fh.read(record_auzonenamet_len)
                record_class = Text_record(token_type.lower(),record_auzonenamet_len,record_auzonenamet_zonename)
                print("len: %s\nzonename: %s" %
                      (record_auzonenamet_len, record_auzonenamet_zonename))
            case b'\x71':
                token_type = "AU_ARG64_T"
                print("\n[+] Type is %s" % token_type)
                record_auarg64t_no = fh.read(1)
                record_auarg64t_val = int.from_bytes(fh.read(8), "big")
                record_auarg64t_len = int.from_bytes(fh.read(2), "big")
                record_auarg64t_text = read_nts_array(fh, record_auarg64t_len)
                record_class = Arg_record(token_type,record_auarg64t_no,record_auarg64t_val,record_auarg64t_len,record_auarg64t_text)

                print("no: %s\nval: %s\nlen: %s\ntext: %s" % (
                    record_auarg64t_no, record_auarg64t_val, record_auarg64t_len, record_arg64t_text))
            case b'\x72':
                token_type = "AU_RET64_T"
                print("\n[+] Type is %s" % token_type)
                au_ret64_t = aurecord.au_ret64_t(fh)
                print_items(au_ret64_t)
                # dumpstruct(au_ret64_t)
            case b'\x73':
                token_type = "AU_ATTR64_T"
                print("\n[+] Type is %s" % token_type)
                au_attr64_t = aurecord.au_attr64_t(fh)
                print_items(au_attr64_t)
                # dumpstruct(au_attr64_t)
            case b'\x74':
                token_type = "AU_HEADER64_t"
                print("\n[+] Type is %s" % token_type)
                au_header64_t = aurecord.au_header64_t(fh)
                print_items(au_header64_t)
                # dumpstruct(au_header64_t)
            case b'\x75':
                token_type = "AU_SUBJECT64_T"
                print("\n[+] Type is %s" % token_type)
                au_subject64_t = aurecord.au_subject64_t(fh)
                print_items(au_subject64_t)
                # dumpstruct(au_subject64_t)
            case b'\x77':
                token_type = "AU_PROCESS64_T"
                print("\n[+] Type is %s" % token_type)
                au_proc64_t = aurecord.au_proc64_t(fh)
                print_items(au_proc64_t)
                # dumpstruct(au_proc64_t)
            case b'\x79':
                token_type = "AU_HEADER64_EX_T"
                print("\n[+] Type is %s" % token_type)
                au_header64_ex_t = aurecord.au_header64_ex_t(fh)
                print_items(au_header64_ex_t)
                # dumpstruct(au_header64_ex_t)
            case b'\x7a':
                token_type = "AU_SUBJECT32EX_T"
                print("\n[+] Type is %s" % token_type)
                au_subject32ex_t = aurecord.au_subject32ex_t(fh)
                print_items(au_subject32ex_t)
                # dumpstruct(au_subject32ex_t)
            case b'\x7b':
                token_type = "AU_PROC32EXT_T"
                print("\n[+] Type is %s" % token_type)
                au_proc32ex_t = aurecord.au_proc32ex_t(fh)
                print_items(au_proc32ex_t)
                # dumpstruct(au_proc32ex_t)
            case b'\x7c':
                token_type = "AU_SUBJECT64EX_T"
                print("\n[+] Type is %s" % token_type)
                au_subject64ex_t = aurecord.au_subject64ex_t(fh)
                print_items(au_subject64ex_t)
                # dumpstruct(au_subject64ex_t)
            case b'\x7d':
                token_type = "AU_PROC64EX_T"
                print("\n[+] Type is %s" % token_type)
                au_proc64ex_t = aurecord.au_proc64ex_t(fh)
                print_items(au_proc64ex_t)
                # dumpstruct(au_proc64ex_t)
            case b'\x7e':
                token_type = "AUINADDR_EX_T"
                print("\n[+] Type is %s" % token_type)
                auinaddr_ex_t = aurecord.auinaddr_ex_t(fh)
                print_items(auinaddr_ex_t)
                # dumpstruct(auinaddr_ex_t)
            case b'':
                print("\nEnd of File reached!\nExiting...")
                not_empty = False
            case _:
                print("\n!invalid record type! %s" % header_type)
                not_empty = False


if __name__ == '__main__':
    main()
