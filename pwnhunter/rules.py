"""Function models for common CTF pwn sources and sinks."""

from __future__ import annotations

import re


_BUNDLED_RUNTIME_SOURCE_PATH = re.compile(
    r"(?:^|[/\\])(?:"
    r"sysdeps[/\\]|"
    r"glibc[/\\]|"
    r"nss(?:_[^/\\]+)?[/\\]|"
    r"resolv[/\\]|"
    r"(?:crypto|ssl|providers|engines)[/\\]|"
    r"rustc[/\\].*[/\\]library[/\\]|"
    r"library[/\\](?:std|core|alloc|panic_abort|unwind)[/\\]src[/\\]|"
    r"go[/\\]src[/\\]runtime[/\\]"
    r")",
    re.IGNORECASE,
)

_BUNDLED_RUNTIME_DIAGNOSTICS = frozenset(
    {
        # glibc resolv/label.c: this internal consistency failure is not a
        # user-facing resolver error and survives in stripped static builds.
        "unsupported label source",
    }
)

_BUNDLED_RUNTIME_SOURCE_BASENAMES = frozenset(
    {
        "arena.c",
        "dl-close.c",
        "dl-load.c",
        "dl-object.c",
        "dl-open.c",
        "dl-reloc.c",
        "dl-runtime.c",
        "dl-tls.c",
        "dl-version.c",
        "getaddrinfo.c",
        "ifaddrs.c",
        "libioP.h",
        "malloc.c",
        "nss_database.c",
        "nsswitch.c",
        "resolv_conf.c",
        "rtld.c",
        # glibc/libio/wfileops.c retains assertion metadata in static builds
        # and implements the internal _IO_wfile_* state machine.
        "wfileops.c",
    }
)


def looks_like_bundled_runtime_source(text: str) -> bool:
    """Return whether a string is strong static-runtime provenance evidence.

    Stripped static executables often retain assertion file names even though
    IDA cannot apply a FLIRT library flag.  Restrict seeds to compiler/runtime
    namespaces and a small set of distinctive glibc basenames; ordinary user
    source paths such as ``src/main.c`` are intentionally not accepted.
    """

    normalized = text.strip().replace("\\", "/")
    if not normalized or len(normalized) > 512:
        return False
    basename = normalized.rsplit("/", 1)[-1]
    return bool(
        _BUNDLED_RUNTIME_SOURCE_PATH.search(normalized)
        or basename in _BUNDLED_RUNTIME_SOURCE_BASENAMES
        or normalized in _BUNDLED_RUNTIME_DIAGNOSTICS
    )


FORMAT_ARGUMENTS: dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "dprintf": 1,
    "vdprintf": 1,
    "sprintf": 1,
    "vsprintf": 1,
    "snprintf": 2,
    "vsnprintf": 2,
    "asprintf": 1,
    "vasprintf": 1,
    "syslog": 1,
    "vsyslog": 1,
    "__printf_chk": 1,
    "__vprintf_chk": 1,
    "__fprintf_chk": 2,
    "__vfprintf_chk": 2,
    "__dprintf_chk": 2,
    "__vdprintf_chk": 2,
    "__sprintf_chk": 3,
    "__vsprintf_chk": 3,
    "__snprintf_chk": 4,
    "__vsnprintf_chk": 4,
    "__asprintf_chk": 2,
    "__vasprintf_chk": 2,
}

# First ordinary variadic argument for printf-family calls whose arguments are
# visible in ctree. The v* entry points receive an opaque va_list and cannot
# be mapped to individual expressions without ABI-specific recovery.
FORMAT_VARIADIC_STARTS: dict[str, int] = {
    "printf": 1,
    "fprintf": 2,
    "dprintf": 2,
    "sprintf": 2,
    "snprintf": 3,
    "asprintf": 2,
    "syslog": 2,
    "__printf_chk": 2,
    "__fprintf_chk": 3,
    "__dprintf_chk": 3,
    "__sprintf_chk": 4,
    "__snprintf_chk": 5,
    "__asprintf_chk": 3,
}


def format_cstring_read_arguments(
    name: str, format_text: str
) -> tuple[tuple[int, int | None, int | None], ...]:
    """Map literal narrow ``%s`` directives to call argument indexes.

    Each result contains the string argument, an optional static precision,
    and an optional dynamic-precision argument. Both precision fields being
    ``None`` means an unbounded scan. POSIX positional arguments and ``*``
    width/precision operands are handled.
    """

    first_argument = FORMAT_VARIADIC_STARTS.get(name)
    if first_argument is None or not format_text:
        return ()

    def positional(index: int) -> tuple[int | None, int]:
        end = index
        while end < len(format_text) and format_text[end].isdigit():
            end += 1
        if (
            end > index
            and end < len(format_text)
            and format_text[end] == "$"
        ):
            value = int(format_text[index:end])
            return (value if value > 0 else None), end + 1
        return None, index

    reads: list[tuple[int, int | None, int | None]] = []
    cursor = 0
    next_argument = 1
    flags = "-+ #0'I"
    while cursor < len(format_text):
        if format_text[cursor] != "%":
            cursor += 1
            continue
        cursor += 1
        if cursor < len(format_text) and format_text[cursor] == "%":
            cursor += 1
            continue

        main_position, positioned_cursor = positional(cursor)
        if main_position is not None:
            cursor = positioned_cursor
        while cursor < len(format_text) and format_text[cursor] in flags:
            cursor += 1

        if cursor < len(format_text) and format_text[cursor] == "*":
            cursor += 1
            width_position, positioned_cursor = positional(cursor)
            if width_position is not None:
                cursor = positioned_cursor
            else:
                next_argument += 1
        else:
            while cursor < len(format_text) and format_text[cursor].isdigit():
                cursor += 1

        precision_present = False
        dynamic_precision = False
        precision_position: int | None = None
        precision = 0
        if cursor < len(format_text) and format_text[cursor] == ".":
            precision_present = True
            cursor += 1
            if cursor < len(format_text) and format_text[cursor] == "*":
                dynamic_precision = True
                cursor += 1
                precision_position, positioned_cursor = positional(cursor)
                if precision_position is not None:
                    cursor = positioned_cursor
                else:
                    precision_position = next_argument
                    next_argument += 1
            else:
                start = cursor
                while cursor < len(format_text) and format_text[cursor].isdigit():
                    cursor += 1
                if cursor > start:
                    precision = int(format_text[start:cursor])

        length = ""
        for candidate in ("hh", "ll", "h", "l", "j", "z", "t", "L", "q"):
            if format_text.startswith(candidate, cursor):
                length = candidate
                cursor += len(candidate)
                break
        if cursor >= len(format_text):
            break
        conversion = format_text[cursor]
        cursor += 1
        if conversion in {"%", "m"}:
            continue

        if main_position is None:
            main_position = next_argument
            next_argument += 1
        if conversion != "s" or length == "l":
            continue
        maximum = precision if precision_present and not dynamic_precision else None
        maximum_argument = (
            first_argument + precision_position - 1
            if dynamic_precision and precision_position is not None
            else None
        )
        item = (
            first_argument + main_position - 1,
            maximum,
            maximum_argument,
        )
        if item not in reads:
            reads.append(item)
    return tuple(reads)

# C APIs that scan an argument until a NUL byte.  A raw byte producer can
# legally fill its destination without appending that byte, so these reads are
# tracked separately from ordinary taint and buffer-write checks.
CSTRING_READ_ARGUMENTS: dict[str, tuple[int, ...]] = {
    "strlen": (0,),
    "strcmp": (0, 1),
    "strcasecmp": (0, 1),
    "strcpy": (1,),
    "stpcpy": (1,),
    "strcat": (0, 1),
    "__strcpy_chk": (1,),
    "__stpcpy_chk": (1,),
    "__strcat_chk": (0, 1),
    "strdup": (0,),
    "strchr": (0,),
    "strrchr": (0,),
    "strstr": (0, 1),
    "puts": (0,),
    "fopen": (0, 1),
    "open": (0,),
    "atoi": (0,),
    "atol": (0,),
    "atoll": (0,),
    "strtol": (0,),
    "strtoul": (0,),
    "strtoll": (0,),
    "strtoull": (0,),
    "strtof": (0,),
    "strtod": (0,),
    "strtold": (0,),
    "strtok": (0, 1),
}

# C-string APIs whose scan is capped by a byte count.  The final flag marks
# pairwise comparisons: either input's terminating NUL also stops reads from
# the other input, so a proven peer-string length is an independent upper
# bound in addition to the explicit count.
# name -> (source arguments, maximum argument, stops at a peer NUL)
BOUNDED_CSTRING_READ_SPECS: dict[
    str, tuple[tuple[int, ...], int, bool]
] = {
    "strnlen": ((0,), 1, False),
    "strndup": ((0,), 1, False),
    "strncmp": ((0, 1), 2, True),
    "strncasecmp": ((0, 1), 2, True),
}

# name -> (destination argument, source argument, length arguments)
COPY_SPECS: dict[str, tuple[int, int, tuple[int, ...]]] = {
    "memcpy": (0, 1, (2,)),
    "memmove": (0, 1, (2,)),
    "__memcpy_chk": (0, 1, (2,)),
    "__memmove_chk": (0, 1, (2,)),
    "__mempcpy_chk": (0, 1, (2,)),
    # Static glibc uses IRELATIVE thunks whose original symbol is absent.
    # The IDA adapter assigns this semantic name only after instruction-level
    # confirmation of the common (dst, src, length) copy contract.
    "memcpy_like": (0, 1, (2,)),
    "bcopy": (1, 0, (2,)),
    "strncpy": (0, 1, (2,)),
    "__strncpy_chk": (0, 1, (2,)),
    "strncat": (0, 1, (2,)),
}

# name -> (destination argument, length arguments)
BOUNDED_WRITE_SPECS: dict[str, tuple[int, tuple[int, ...]]] = {
    "read": (1, (2,)),
    "pread": (1, (2,)),
    "recv": (1, (2,)),
    "recvfrom": (1, (2,)),
    "fread": (0, (1, 2)),
    "fgets": (0, (1,)),
    "memset": (0, (2,)),
    "snprintf": (0, (1,)),
    "vsnprintf": (0, (1,)),
    "readlink": (1, (2,)),
    "getrandom": (0, (1,)),
    "__read_chk": (1, (2,)),
    "__pread_chk": (1, (2,)),
    "__recv_chk": (1, (2,)),
    "__recvfrom_chk": (1, (2,)),
    "__fread_chk": (0, (2, 3)),
    "__fgets_chk": (0, (2,)),
    "__memset_chk": (0, (2,)),
    "__snprintf_chk": (0, (1,)),
    "__vsnprintf_chk": (0, (1,)),
    "__readlink_chk": (1, (2,)),
}

# Fortify entry point -> compiler-provided destination object-size argument.
# A trusted finite value makes the destination write fail closed before the
# underlying operation; SIZE_MAX means the compiler could not recover a size.
FORTIFIED_DESTINATION_SPECS: dict[str, int] = {
    "__memcpy_chk": 3,
    "__memmove_chk": 3,
    "__mempcpy_chk": 3,
    "__strcpy_chk": 2,
    "__stpcpy_chk": 2,
    "__strncpy_chk": 3,
    "__strcat_chk": 2,
    "__sprintf_chk": 2,
    "__vsprintf_chk": 2,
    "__memset_chk": 3,
    "__read_chk": 3,
    "__pread_chk": 4,
    "__recv_chk": 3,
    "__recvfrom_chk": 3,
    "__fread_chk": 1,
    "__fgets_chk": 1,
    "__snprintf_chk": 3,
    "__vsnprintf_chk": 3,
    "__readlink_chk": 3,
}

# APIs that consume bytes from a caller-owned buffer.  Their byte-count
# arguments are security-sensitive even though they do not write into that
# buffer: an uninitialized or wrapped count can disclose adjacent memory.
# name -> (source argument, length arguments)
BOUNDED_READ_SPECS: dict[str, tuple[int, tuple[int, ...]]] = {
    "write": (1, (2,)),
    "pwrite": (1, (2,)),
    "send": (1, (2,)),
    "sendto": (1, (2,)),
    "fwrite": (0, (1, 2)),
    "memchr": (0, (2,)),
    "memrchr": (0, (2,)),
}

# APIs that read the same byte count from multiple caller-owned objects.
# Unlike strncmp, memcmp/bcmp never stop at a NUL byte, so both object ranges
# must be valid for the complete count.
# name -> (source arguments, length arguments)
BOUNDED_MULTI_READ_SPECS: dict[
    str, tuple[tuple[int, ...], tuple[int, ...]]
] = {
    "memcmp": ((0, 1), (2,)),
    "bcmp": ((0, 1), (2,)),
}

# Scatter/gather output APIs.  The vector descriptor array is itself read,
# then every reachable ``iov_base`` is consumed for its paired ``iov_len``.
# name -> (iovec argument, iovec-count argument)
IOVEC_READ_SPECS: dict[str, tuple[int, int]] = {
    "writev": (1, 2),
    "pwritev": (1, 2),
    "pwritev64": (1, 2),
    "pwritev2": (1, 2),
}

# Scatter/gather input APIs.  The vector descriptor array is read by the
# kernel, then bytes are written through every reachable ``iov_base`` for at
# most its paired ``iov_len``.
# name -> (iovec argument, iovec-count argument)
IOVEC_WRITE_SPECS: dict[str, tuple[int, int]] = {
    "readv": (1, 2),
    "preadv": (1, 2),
    "preadv64": (1, 2),
    "preadv2": (1, 2),
}

# Socket message APIs.  Unlike readv/writev, their scatter/gather vector and
# count live inside struct msghdr.  A None count index denotes one msghdr;
# sendmmsg/recvmmsg instead receive an array of struct mmsghdr plus a count.
# name -> (message argument, optional message-count argument)
MESSAGE_READ_SPECS: dict[str, tuple[int, int | None]] = {
    "sendmsg": (1, None),
    "sendmmsg": (1, 2),
}

MESSAGE_WRITE_SPECS: dict[str, tuple[int, int | None]] = {
    "recvmsg": (1, None),
    "recvmmsg": (1, 2),
}

# name -> (destination argument, optional source argument)
UNBOUNDED_WRITE_SPECS: dict[str, tuple[int, int | None]] = {
    "gets": (0, None),
    "strcpy": (0, 1),
    "stpcpy": (0, 1),
    "strcat": (0, 1),
    "__strcpy_chk": (0, 1),
    "__stpcpy_chk": (0, 1),
    "__strcat_chk": (0, 1),
    "__sprintf_chk": (0, None),
    "__vsprintf_chk": (0, None),
    "wcscpy": (0, 1),
    "sprintf": (0, None),
    "vsprintf": (0, None),
}

# Direct external-input functions and the arguments they write through.
INPUT_WRITES: dict[str, tuple[int, ...]] = {
    "read": (1,),
    "pread": (1,),
    "recv": (1,),
    "recvfrom": (1,),
    "fread": (0,),
    "fgets": (0,),
    "gets": (0,),
    "getline": (0,),
    "getdelim": (0,),
    "readlink": (1,),
    "__read_chk": (1,),
    "__pread_chk": (1,),
    "__recv_chk": (1,),
    "__recvfrom_chk": (1,),
    "__fread_chk": (0,),
    "__fgets_chk": (0,),
    "__readlink_chk": (1,),
}

# name -> (format argument, first output argument, source argument or None).
# A None source means input is external (stdin/FILE).
SCANF_SPECS: dict[str, tuple[int, int, int | None]] = {
    "scanf": (0, 1, None),
    "fscanf": (1, 2, None),
    "sscanf": (1, 2, 0),
}

ALLOC_SPECS: dict[str, tuple[int, ...]] = {
    "malloc": (0,),
    "calloc": (0, 1),
    "realloc": (1,),
    "reallocarray": (1, 2),
    "aligned_alloc": (1,),
    "mmap": (1,),
    "mmap64": (1,),
}

REALLOC_NAMES = frozenset({"realloc", "reallocarray"})

FREE_NAMES = {"free", "cfree", "operator delete", "operator delete[]"}

# Functions used to seed the fast IDA scan. The selector walks callers of
# these symbols before decompiling anything, which matters for statically
# linked challenge binaries containing thousands of library functions.
SCAN_SEED_NAMES = (
    set(FORMAT_ARGUMENTS)
    | set(COPY_SPECS)
    | set(BOUNDED_WRITE_SPECS)
    | set(BOUNDED_READ_SPECS)
    | set(BOUNDED_MULTI_READ_SPECS)
    | set(BOUNDED_CSTRING_READ_SPECS)
    | set(IOVEC_READ_SPECS)
    | set(IOVEC_WRITE_SPECS)
    | set(MESSAGE_READ_SPECS)
    | set(MESSAGE_WRITE_SPECS)
    | set(UNBOUNDED_WRITE_SPECS)
    | set(SCANF_SPECS)
    | set(CSTRING_READ_ARGUMENTS)
    | set(ALLOC_SPECS)
    | FREE_NAMES
    | {
        "iconv",
        "iconv_open",
        "mmap",
        "munmap",
        "brk",
        "pthread_create",
        "clone",
        "system",
        "execve",
    }
)

# The return value itself is affected by external input.
RETURN_SOURCES = {
    "read",
    "pread",
    "recv",
    "recvfrom",
    "fread",
    "fgets",
    "gets",
    "getchar",
    "getc",
    "fgetc",
    "getline",
    "getdelim",
    "__read_chk",
    "__pread_chk",
    "__recv_chk",
    "__recvfrom_chk",
    "__fread_chk",
    "__fgets_chk",
    "__readlink_chk",
    "readv",
    "preadv",
    "preadv64",
    "preadv2",
    "recvmsg",
    "recvmmsg",
}

# Input APIs whose integral return domain contains a distinguished -1 failure
# value. Pointer-returning routines and fread's zero/short-count contract are
# intentionally excluded: converting those requires different reasoning.
ERROR_SENTINEL_RETURNS = frozenset(
    {
        "read",
        "pread",
        "recv",
        "recvfrom",
        "readlink",
        "__read_chk",
        "__pread_chk",
        "__recv_chk",
        "__recvfrom_chk",
        "__readlink_chk",
        "readv",
        "preadv",
        "preadv64",
        "preadv2",
        "recvmsg",
        "recvmmsg",
        "getline",
        "getdelim",
        "getchar",
        "getc",
        "fgetc",
    }
)

# Successful return values are bounded by these argument products. fread is
# included even though it has no -1 sentinel because the range proof is also
# useful for ordinary conversion and allocation arithmetic analysis.
SUCCESS_RETURN_LENGTH_SPECS: dict[str, tuple[int, ...]] = {
    "read": (2,),
    "pread": (2,),
    "recv": (2,),
    "recvfrom": (2,),
    "readlink": (2,),
    "__read_chk": (2,),
    "__pread_chk": (2,),
    "__recv_chk": (2,),
    "__recvfrom_chk": (2,),
    "__readlink_chk": (2,),
    # fread returns completed elements, not transferred bytes.
    "fread": (2,),
    "__fread_chk": (3,),
}

# Return value is tainted if any argument is tainted.
TAINT_PASSTHROUGH_RETURNS = {
    "atoi",
    "atol",
    "atoll",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "strtof",
    "strtod",
    "strtold",
    "strlen",
    "strnlen",
    "strchr",
    "strstr",
    "memchr",
    "strdup",
    "strndup",
    "strtok",
}

# Stateful tokenizers whose null input argument continues a prior session.
# A non-null input replaces the session, including resetting it to clean data.
STATEFUL_TAINT_RETURNS: dict[str, int] = {
    "strtok": 0,
}


_ALIASES = {
    "__isoc99_scanf": "scanf",
    "__isoc99_fscanf": "fscanf",
    "__isoc99_sscanf": "sscanf",
    "__isoc23_scanf": "scanf",
    "__isoc23_fscanf": "fscanf",
    "__isoc23_sscanf": "sscanf",
    "__isoc23_strtol": "strtol",
    "__isoc23_strtoul": "strtoul",
    "__isoc23_strtoll": "strtoll",
    "__isoc23_strtoull": "strtoull",
    "__libc_malloc": "malloc",
    "__libc_calloc": "calloc",
    "__libc_realloc": "realloc",
    "__libc_reallocarray": "reallocarray",
    "__libc_free": "free",
    "__mmap": "mmap",
    "__mmap64": "mmap64",
    "_IO_getc": "getc",
    "_IO_fgets": "fgets",
}

_KNOWN_NAMES = (
    set(FORMAT_ARGUMENTS)
    | set(COPY_SPECS)
    | set(BOUNDED_WRITE_SPECS)
    | set(BOUNDED_READ_SPECS)
    | set(BOUNDED_MULTI_READ_SPECS)
    | set(BOUNDED_CSTRING_READ_SPECS)
    | set(IOVEC_READ_SPECS)
    | set(IOVEC_WRITE_SPECS)
    | set(MESSAGE_READ_SPECS)
    | set(MESSAGE_WRITE_SPECS)
    | set(UNBOUNDED_WRITE_SPECS)
    | set(INPUT_WRITES)
    | set(SCANF_SPECS)
    | set(CSTRING_READ_ARGUMENTS)
    | set(ALLOC_SPECS)
    | FREE_NAMES
    | RETURN_SOURCES
    | TAINT_PASSTHROUGH_RETURNS
    | set(STATEFUL_TAINT_RETURNS)
    | set(_ALIASES)
)


def normalize_symbol(raw_name: str) -> str:
    """Normalize common ELF/Mach-O import and thunk spellings."""

    name = raw_name.strip()
    name = re.sub(r"(@@?|\\$)[A-Za-z_][A-Za-z0-9_.-]*$", "", name)
    for prefix in ("__imp_", "imp_", "j_", "thunk_", "."):
        if name.startswith(prefix):
            name = name[len(prefix) :]
    # Mach-O C symbols have one ABI underscore. Keep Linux implementation
    # names such as __printf_chk intact, while still handling Mach-O's
    # ___printf_chk spelling.
    if name.startswith("_") and (
        not name.startswith("__") or name[1:] in _KNOWN_NAMES
    ):
        name = name[1:]
    return _ALIASES.get(name, name)
