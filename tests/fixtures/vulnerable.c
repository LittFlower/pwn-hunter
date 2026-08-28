#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * Keep the Linux userspace layout even when this fixture is built as a
 * Mach-O on the development host.  The binary is never executed; IDA only
 * needs real ctree for the Linux sendmsg/recvmsg contract modeled by the
 * plugin.
 */
struct pwnhunter_msghdr {
    void *msg_name;
    unsigned int msg_namelen;
    unsigned int padding;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
    int trailing_padding;
};

extern ssize_t sendmsg(
    int descriptor,
    const struct pwnhunter_msghdr *message,
    int flags
);
extern ssize_t recvmsg(
    int descriptor,
    struct pwnhunter_msghdr *message,
    int flags
);

extern char *__strcpy_chk(
    char *destination,
    const char *source,
    size_t destination_capacity
);

extern char *__strncpy_chk(
    char *destination,
    const char *source,
    size_t count,
    size_t destination_capacity
);

extern int __sprintf_chk(
    char *destination,
    int flag,
    size_t destination_capacity,
    const char *format,
    ...
);

__attribute__((noinline))
static void *reallocarray(void *old, size_t count, size_t width) {
    if (width != 0 && count > SIZE_MAX / width) {
        return NULL;
    }
    return realloc(old, count * width);
}

__attribute__((noinline))
static void *__memcpy_chk(
    void *destination,
    const void *source,
    size_t count,
    size_t destination_capacity
) {
    if (count > destination_capacity) {
        abort();
    }
    return memcpy(destination, source, count);
}

__attribute__((noinline))
static ssize_t __read_chk(
    int descriptor,
    void *destination,
    size_t count,
    size_t destination_capacity
) {
    if (count > destination_capacity) {
        abort();
    }
    return read(descriptor, destination, count);
}

__attribute__((noinline))
static int __isoc23_scanf(const char *format, unsigned int *output) {
    return scanf(format, output);
}

static volatile int comparison_sink;
static volatile int relational_status_sink;
static volatile double parsed_sink;
static volatile size_t string_length_sink;
static volatile size_t error_result_size;
static volatile size_t dynamic_length_sink;

struct error_output_record {
    size_t count;
    size_t status;
};

static struct error_output_record error_output_record;

__attribute__((noinline))
static void compare_bytes_wrapper(
    const void *left,
    const void *right,
    size_t count
) {
    comparison_sink = memcmp(left, right, count);
}

__attribute__((noinline))
static void memchr_source_overread(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    comparison_sink = memchr(source, 'A', sizeof(source) + 1) != NULL;
}

__attribute__((noinline))
static void memchr_exact_source(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    comparison_sink = memchr(source, 'A', sizeof(source)) != NULL;
}

__attribute__((noinline))
static void bcmp_first_source_overread(void) {
    char left[8];
    char right[16] = {0};
    read(STDIN_FILENO, left, sizeof(left));
    comparison_sink = bcmp(left, right, sizeof(right));
}

__attribute__((noinline))
static void writev_first_source_overread(void) {
    char source[8];
    struct iovec vector;
    read(STDIN_FILENO, source, sizeof(source));
    vector.iov_base = source;
    vector.iov_len = sizeof(source) + 1;
    writev(STDOUT_FILENO, &vector, 1);
}

__attribute__((noinline))
static void writev_exact_source(void) {
    char source[8] = {0};
    struct iovec vector;
    read(STDIN_FILENO, source, sizeof(source) - 1);
    vector.iov_base = source;
    vector.iov_len = sizeof(source);
    writev(STDOUT_FILENO, &vector, 1);
}

__attribute__((noinline))
static void writev_iovec_array_overread(void) {
    char source[8] = {0};
    struct iovec vector;
    read(STDIN_FILENO, source, sizeof(source) - 1);
    vector.iov_base = source;
    vector.iov_len = sizeof(source);
    writev(STDOUT_FILENO, &vector, 2);
}

__attribute__((noinline))
static void writev_second_source_overread(void) {
    char first[16] = {0};
    char second[8];
    struct iovec vectors[2];
    read(STDIN_FILENO, second, sizeof(second));
    vectors[0].iov_base = first;
    vectors[0].iov_len = sizeof(first);
    vectors[1].iov_base = second;
    vectors[1].iov_len = sizeof(second) + 1;
    writev(STDOUT_FILENO, vectors, 2);
}

__attribute__((noinline))
static ssize_t writev_wrapper(const struct iovec *vectors, int count) {
    return writev(STDOUT_FILENO, vectors, count);
}

__attribute__((noinline))
static void wrapped_writev_source_overread(void) {
    char source[8];
    struct iovec vector;
    read(STDIN_FILENO, source, sizeof(source));
    vector.iov_base = source;
    vector.iov_len = sizeof(source) + 1;
    writev_wrapper(&vector, 1);
}

__attribute__((noinline))
static void readv_first_destination_overflow(void) {
    char destination[64] = {0};
    struct iovec vector;
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination) + 1;
    readv(STDIN_FILENO, &vector, 1);
    comparison_sink ^= destination[63];
}

__attribute__((noinline))
static void readv_exact_destination(void) {
    char destination[64] = {0};
    struct iovec vector;
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination);
    readv(STDIN_FILENO, &vector, 1);
    comparison_sink ^= destination[63];
}

__attribute__((noinline))
static void readv_iovec_array_overread(void) {
    char destination[64] = {0};
    struct iovec vector;
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination);
    readv(STDIN_FILENO, &vector, 2);
    comparison_sink ^= destination[63];
}

__attribute__((noinline))
static void readv_second_destination_overflow(void) {
    char first[128] = {0};
    char second[64] = {0};
    struct iovec vectors[2];
    vectors[0].iov_base = first;
    vectors[0].iov_len = sizeof(first);
    vectors[1].iov_base = second;
    vectors[1].iov_len = sizeof(second) + 1;
    readv(STDIN_FILENO, vectors, 2);
    comparison_sink ^= first[127] ^ second[63];
}

__attribute__((noinline))
static ssize_t readv_wrapper(struct iovec *vectors, int count) {
    return readv(STDIN_FILENO, vectors, count);
}

__attribute__((noinline))
static void wrapped_readv_destination_overflow(void) {
    char destination[64] = {0};
    struct iovec vector;
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination) + 1;
    readv_wrapper(&vector, 1);
    comparison_sink ^= destination[63];
}

__attribute__((noinline))
static void readv_unterminated_printf(void) {
    char destination[64] = {0};
    struct iovec vector;
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination);
    readv(STDIN_FILENO, &vector, 1);
    comparison_sink ^= destination[63];
    printf("%s", destination);
}

__attribute__((noinline))
static void sendmsg_payload_source_overread(void) {
    char source[64];
    struct iovec vector;
    struct pwnhunter_msghdr message = {0};
    read(STDIN_FILENO, source, sizeof(source));
    vector.iov_base = source;
    vector.iov_len = sizeof(source) + 1;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    sendmsg(STDOUT_FILENO, &message, 0);
}

__attribute__((noinline))
static void sendmsg_control_source_overread(void) {
    char control[64];
    struct pwnhunter_msghdr message = {0};
    read(STDIN_FILENO, control, sizeof(control));
    message.msg_control = control;
    message.msg_controllen = sizeof(control) + 1;
    sendmsg(STDOUT_FILENO, &message, 0);
}

__attribute__((noinline))
static void sendmsg_exact_source(void) {
    char source[64] = {0};
    struct iovec vector;
    struct pwnhunter_msghdr message = {0};
    vector.iov_base = source;
    vector.iov_len = sizeof(source);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    sendmsg(STDOUT_FILENO, &message, 0);
}

__attribute__((noinline))
static void sendmsg_header_overread(void) {
    char short_header[48] = {0};
    sendmsg(
        STDOUT_FILENO,
        (const struct pwnhunter_msghdr *)short_header,
        0
    );
}

__attribute__((noinline))
static void recvmsg_payload_destination_overflow(void) {
    char destination[64] = {0};
    struct iovec vector;
    struct pwnhunter_msghdr message = {0};
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination) + 1;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    recvmsg(STDIN_FILENO, &message, 0);
    comparison_sink ^= destination[63];
}

__attribute__((noinline))
static ssize_t recvmsg_wrapper(struct pwnhunter_msghdr *message) {
    return recvmsg(STDIN_FILENO, message, 0);
}

__attribute__((noinline))
static void wrapped_recvmsg_destination_overflow(void) {
    char destination[64] = {0};
    struct iovec vector;
    struct pwnhunter_msghdr message = {0};
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination) + 1;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    recvmsg_wrapper(&message);
    comparison_sink ^= destination[63];
}

__attribute__((noinline))
static void recvmsg_unterminated_printf(void) {
    char destination[64] = {0};
    struct iovec vector;
    struct pwnhunter_msghdr message = {0};
    vector.iov_base = destination;
    vector.iov_len = sizeof(destination);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    recvmsg(STDIN_FILENO, &message, 0);
    comparison_sink ^= destination[63];
    printf("%s", destination);
}

__attribute__((noinline))
static char *second_token(char *input) {
    (void)strtok(input, " ");
    return strtok(NULL, " ");
}

__attribute__((noinline))
static void format_string(void) {
    char buffer[32];
    read(STDIN_FILENO, buffer, sizeof(buffer));
    printf(buffer);
}

__attribute__((noinline))
static void format_string_argument_wrapper(const char *source) {
    printf("wrapped=%s!", source);
}

__attribute__((noinline))
static void unterminated_printf_argument(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    printf("value=%s!", source);
}

__attribute__((noinline))
static void wrapped_unterminated_printf_argument(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    format_string_argument_wrapper(source);
}

__attribute__((noinline))
static void bounded_printf_argument(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    printf("%.8s", source);
}

__attribute__((noinline))
static void oversized_precision_printf_argument(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    printf("%.9s", source);
}

__attribute__((noinline))
static size_t bounded_length_wrapper(const char *source, size_t maximum) {
    return strnlen(source, maximum);
}

__attribute__((noinline))
static void oversized_strnlen(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    string_length_sink = strnlen(source, sizeof(source) + 1);
}

__attribute__((noinline))
static void wrapped_oversized_strnlen(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    string_length_sink = bounded_length_wrapper(source, sizeof(source) + 1);
}

__attribute__((noinline))
static void bounded_strnlen_exact(void) {
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    string_length_sink = strnlen(source, sizeof(source));
}

__attribute__((noinline))
static void oversized_strncmp(void) {
    char source[4];
    read(STDIN_FILENO, source, sizeof(source));
    comparison_sink = strncmp(source, "ABCD", 100);
}

__attribute__((noinline))
static void short_peer_strncmp(void) {
    char source[4];
    read(STDIN_FILENO, source, sizeof(source));
    comparison_sink = strncmp(source, "X", 100);
}

__attribute__((noinline))
static void unsafe_dynamic_precision_wrapper(
    int precision,
    const char *source
) {
    printf("%.*s", precision, source);
}

__attribute__((noinline))
static void guarded_dynamic_precision_wrapper(
    int precision,
    const char *source
) {
    printf("%.*s", precision, source);
}

__attribute__((noinline))
static void unsafe_dynamic_precision_printf_argument(void) {
    int precision;
    char source[8];
    read(STDIN_FILENO, &precision, sizeof(precision));
    read(STDIN_FILENO, source, sizeof(source));
    unsafe_dynamic_precision_wrapper(precision, source);
}

__attribute__((noinline))
static void guarded_dynamic_precision_printf_argument(void) {
    int precision;
    char source[8];
    read(STDIN_FILENO, &precision, sizeof(precision));
    read(STDIN_FILENO, source, sizeof(source));
    if (precision >= 0 && precision <= (int)sizeof(source)) {
        guarded_dynamic_precision_wrapper(precision, source);
    }
}

__attribute__((noinline))
static void stack_overflow(void) {
    char buffer[32];
    read(STDIN_FILENO, buffer, 128);
}

__attribute__((noinline))
static void scanf_overflow(void) {
    char buffer[16];
    scanf("%16s", buffer);
}

__attribute__((noinline))
static void heap_overflow(void) {
    char *buffer = malloc(16);
    read(STDIN_FILENO, buffer, 64);
    free(buffer);
}

__attribute__((noinline))
static void dynamic_heap_off_by_one(void) {
    unsigned int size;
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    if (size < 8 || size > 1024) {
        return;
    }
    char *buffer = malloc(size);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, size + 1);
        free(buffer);
    }
}

__attribute__((noinline))
static void dynamic_heap_source_overread(void) {
    unsigned int size;
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    if (size < 8 || size > 1024) {
        return;
    }
    char *buffer = malloc(size);
    if (buffer != NULL) {
        memset(buffer, 'A', size);
        write(STDOUT_FILENO, buffer, size + 1);
        free(buffer);
    }
}

__attribute__((noinline))
static void output_wrapper(const char *source, size_t count) {
    write(STDOUT_FILENO, source, count);
}

__attribute__((noinline))
static void wrapped_dynamic_heap_source_overread(void) {
    unsigned int size;
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    if (size < 8 || size > 1024) {
        return;
    }
    char *buffer = malloc(size);
    if (buffer != NULL) {
        memset(buffer, 'B', size);
        output_wrapper(buffer, size + 2);
        free(buffer);
    }
}

__attribute__((noinline))
static void short_read_tail_leak(void) {
    char buffer[32];
    read(STDIN_FILENO, buffer, sizeof(buffer));
    write(STDOUT_FILENO, buffer, sizeof(buffer));
}

__attribute__((noinline))
static void checked_full_read_output(void) {
    char buffer[32];
    ssize_t received = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (received != sizeof(buffer)) {
        return;
    }
    write(STDOUT_FILENO, buffer, sizeof(buffer));
}

__attribute__((noinline))
static void allocation_addition_wrap(void) {
    unsigned int size;
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    char *buffer = malloc(size + 32U);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, size);
        free(buffer);
    }
}

__attribute__((noinline))
static void checked_allocation_addition(void) {
    unsigned int size;
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    if (size > UINT_MAX - 32U) {
        return;
    }
    char *buffer = malloc(size + 32U);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, size);
        free(buffer);
    }
}

__attribute__((noinline))
static char *scalar_allocation_inner(size_t size) {
    return malloc(size + 16U);
}

__attribute__((noinline))
static char *scalar_allocation_outer(size_t size) {
    return scalar_allocation_inner(size + 8U);
}

__attribute__((noinline))
static void scalar_allocation_summary_overflow(void) {
    size_t size;
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    char *buffer = scalar_allocation_inner(size);
    if (buffer != NULL) {
        free(buffer);
    }
}

__attribute__((noinline))
static void scalar_allocation_capacity_overflow(void) {
    char *buffer = scalar_allocation_outer(8U);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, 33U);
        free(buffer);
    }
}

__attribute__((noinline))
static void scalar_allocation_capacity_exact(void) {
    char *buffer = scalar_allocation_outer(8U);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, 32U);
        free(buffer);
    }
}

__attribute__((noinline))
static void bounded_read_result_allocation(void) {
    char input[32];
    ssize_t received = read(STDIN_FILENO, input, sizeof(input));
    char *buffer = scalar_allocation_inner(received);
    if (buffer != NULL) {
        free(buffer);
    }
}

__attribute__((noinline))
static void checked_calloc_implicit_product(void) {
    size_t count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    char *buffer = calloc(count, 16U);
    if (buffer != NULL) {
        free(buffer);
    }
}

__attribute__((noinline))
static void reallocarray_off_by_one(void) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    char *buffer = reallocarray(NULL, count, 16U);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, (size_t)count * 16U + 1U);
        free(buffer);
    }
}

__attribute__((noinline))
static void safe_reallocarray_fill(void) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    char *buffer = reallocarray(NULL, count, 16U);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, (size_t)count * 16U);
        free(buffer);
    }
}

__attribute__((noinline))
static void aligned_alloc_overflow(void) {
    char *buffer = aligned_alloc(16, 32);
    if (buffer != NULL) {
        read(STDIN_FILENO, buffer, 64);
        free(buffer);
    }
}

__attribute__((noinline))
static void fortified_copy_source_overread(void) {
    char destination[16];
    char *source = malloc(8);
    if (source != NULL) {
        __memcpy_chk(destination, source, 16, sizeof(destination));
        free(source);
    }
}

__attribute__((noinline))
static void active_fortified_copy_abort(void) {
    char destination[8];
    char source[16] = {0};
    __memcpy_chk(destination, source, sizeof(source), sizeof(destination));
}

__attribute__((noinline))
static void disabled_fortified_copy_overflow(void) {
    char destination[8];
    char source[16] = {0};
    __memcpy_chk(destination, source, sizeof(source), SIZE_MAX);
}

__attribute__((noinline))
static ssize_t fortified_read_wrapper(
    int descriptor,
    void *destination,
    size_t count,
    size_t destination_capacity
) {
    return __read_chk(
        descriptor,
        destination,
        count,
        destination_capacity
    );
}

__attribute__((noinline))
static void wrapped_fortified_read_unterminated(void) {
    char destination[8];
    fortified_read_wrapper(
        STDIN_FILENO,
        destination,
        sizeof(destination),
        sizeof(destination)
    );
    string_length_sink = strlen(destination);
}

__attribute__((noinline))
static void active_fortified_read_abort(void) {
    char destination[8];
    read(STDIN_FILENO, destination, sizeof(destination));
    fortified_read_wrapper(
        STDIN_FILENO,
        destination,
        sizeof(destination) * 2,
        sizeof(destination)
    );
    string_length_sink = strlen(destination);
}

__attribute__((noinline))
static char *fortified_strncpy_wrapper(
    char *destination,
    const char *source,
    size_t count,
    size_t destination_capacity
) {
    return __strncpy_chk(destination, source, count, destination_capacity);
}

__attribute__((noinline))
static void active_fortified_strncpy_abort(void) {
    char destination[8] = {0};
    char source[16];
    read(STDIN_FILENO, source, sizeof(source));
    fortified_strncpy_wrapper(
        destination,
        source,
        sizeof(source),
        sizeof(destination)
    );
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void disabled_fortified_strncpy_overflow(void) {
    volatile char destination[64] = {0};
    char source[128];
    read(STDIN_FILENO, source, sizeof(source));
    fortified_strncpy_wrapper(
        (char *)destination,
        source,
        sizeof(source),
        SIZE_MAX
    );
    comparison_sink = destination[63];
}

__attribute__((noinline))
static void fortified_strncpy_source_overread(void) {
    char destination[16] = {0};
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    fortified_strncpy_wrapper(
        destination,
        source,
        sizeof(destination),
        sizeof(destination)
    );
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void fortified_strncpy_unterminated_destination(void) {
    char destination[8] = {0};
    char source[8];
    read(STDIN_FILENO, source, sizeof(source));
    __strncpy_chk(destination, source, sizeof(destination), sizeof(destination));
    comparison_sink = (int)strlen(destination);
}

__attribute__((noinline))
static void isoc23_scanf_length(void) {
    volatile char destination[32] = {0};
    unsigned int count;
    __isoc23_scanf("%u", &count);
    read(STDIN_FILENO, (void *)destination, count);
    write(STDOUT_FILENO, (const void *)destination, 1);
}

__attribute__((noinline))
static void memcmp_first_source_overread(void) {
    char left[8];
    char right[16] = {0};
    read(STDIN_FILENO, left, sizeof(left));
    comparison_sink = memcmp(left, right, sizeof(right));
}

__attribute__((noinline))
static void memcmp_second_source_overread(void) {
    char left[16] = {0};
    char right[9];
    for (size_t index = 0; index < sizeof(right); ++index) {
        right[index] = (char)index;
    }
    comparison_sink = memcmp(left, right, sizeof(left));
}

__attribute__((noinline))
static void wrapped_memcmp_source_overread(void) {
    char left[16] = {0};
    char right[9];
    for (size_t index = 0; index < sizeof(right); ++index) {
        right[index] = (char)index;
    }
    compare_bytes_wrapper(left, right, sizeof(left));
}

__attribute__((noinline))
static void safe_memcmp_exact(void) {
    char left[8] = {0};
    char right[8] = {0};
    comparison_sink = memcmp(left, right, sizeof(left));
    compare_bytes_wrapper(left, right, sizeof(left));
}

__attribute__((noinline))
static void stateful_strtok_format(void) {
    char buffer[64] = {0};
    read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
    char *format = second_token(buffer);
    if (format != NULL) {
        printf(format);
    }
}

__attribute__((noinline))
static void unterminated_strtok_input(void) {
    char buffer[8];
    read(STDIN_FILENO, buffer, sizeof(buffer));
    comparison_sink = strtok(buffer, ",") != NULL;
}

__attribute__((noinline))
static void clean_strtok_reset(void) {
    char hostile[32] = {0};
    char clean[] = "literal text";
    read(STDIN_FILENO, hostile, sizeof(hostile) - 1);
    (void)strtok(hostile, " ");
    (void)strtok(clean, " ");
    char *safe = strtok(NULL, " ");
    if (safe != NULL) {
        printf(safe);
    }
}

__attribute__((noinline))
static void strtod_length(void) {
    char text[32] = {0};
    char destination[32] = {0};
    read(STDIN_FILENO, text, sizeof(text) - 1);
    double parsed = strtod(text, NULL);
    size_t count = (size_t)parsed;
    read(STDIN_FILENO, destination, count);
    write(STDOUT_FILENO, destination, 1);
}

__attribute__((noinline))
static void unterminated_strtod_input(void) {
    char text[8];
    read(STDIN_FILENO, text, sizeof(text));
    parsed_sink = strtod(text, NULL);
}

__attribute__((noinline))
static void constant_strtod_length(void) {
    char destination[32] = {0};
    size_t count = (size_t)strtod("12.5", NULL);
    read(STDIN_FILENO, destination, count);
    write(STDOUT_FILENO, destination, 1);
}

__attribute__((noinline))
static void unterminated_strcpy_source(void) {
    char source[8];
    char destination[32] = {0};
    read(STDIN_FILENO, source, sizeof(source));
    strcpy(destination, source);
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void terminated_strcpy_source(void) {
    char source[8] = {0};
    char destination[32] = {0};
    read(STDIN_FILENO, source, sizeof(source) - 1);
    strcpy(destination, source);
    comparison_sink = destination[0];
}

__attribute__((noinline))
static char *fortified_strcpy_wrapper(
    char *destination,
    const char *source,
    size_t destination_capacity
) {
    return __strcpy_chk(destination, source, destination_capacity);
}

__attribute__((noinline))
static void active_fortified_strcpy_abort(void) {
    char destination[8] = {0};
    fortified_strcpy_wrapper(destination, "0123456789", sizeof(destination));
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void disabled_fortified_strcpy_overflow(void) {
    char destination[8] = {0};
    fortified_strcpy_wrapper(destination, "0123456789", SIZE_MAX);
    comparison_sink = destination[0];
}

__attribute__((noinline))
static int fortified_sprintf_wrapper(
    char *destination,
    size_t destination_capacity
) {
    return __sprintf_chk(
        destination,
        0,
        destination_capacity,
        "0123456789"
    );
}

__attribute__((noinline))
static void active_fortified_sprintf_abort(void) {
    char destination[8] = {0};
    fortified_sprintf_wrapper(destination, sizeof(destination));
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void disabled_fortified_sprintf_overflow(void) {
    char destination[8] = {0};
    fortified_sprintf_wrapper(destination, SIZE_MAX);
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void fortified_sprintf_unterminated_source(void) {
    char source[8];
    char destination[32] = {0};
    read(STDIN_FILENO, source, sizeof(source));
    __sprintf_chk(destination, 0, sizeof(destination), "%s", source);
    comparison_sink = destination[0];
}

__attribute__((noinline))
static void use_after_free(void) {
    char *buffer = malloc(32);
    free(buffer);
    puts(buffer);
}

__attribute__((noinline))
static void input_wrapper(char *destination, size_t count) {
    read(STDIN_FILENO, destination, count);
}

__attribute__((noinline))
static void wrapped_stack_overflow(void) {
    char buffer[16];
    input_wrapper(buffer, 64);
}

__attribute__((noinline))
static ssize_t scalar_length_read_wrapper(
    char *destination,
    size_t count
) {
    return read(STDIN_FILENO, destination, count + 8U);
}

__attribute__((noinline))
static void wrapped_scalar_length_overflow(void) {
    char destination[32];
    scalar_length_read_wrapper(destination, 25U);
}

__attribute__((noinline))
static void wrapped_scalar_length_exact(void) {
    char destination[32];
    scalar_length_read_wrapper(destination, 24U);
}

__attribute__((noinline))
static ssize_t input_offset_wrapper(char *destination, size_t count) {
    return read(STDIN_FILENO, destination + 24, count);
}

__attribute__((noinline))
static void wrapped_offset_destination_overflow(void) {
    char destination[32];
    input_offset_wrapper(destination, 16);
}

__attribute__((noinline))
static void wrapped_offset_destination_exact(void) {
    char destination[40];
    input_offset_wrapper(destination, 16);
}

__attribute__((noinline))
static ssize_t output_offset_inner(const char *source, size_t count) {
    return write(STDOUT_FILENO, source + 8, count);
}

__attribute__((noinline))
static ssize_t output_offset_outer(const char *source, size_t count) {
    return output_offset_inner(source + 8, count);
}

__attribute__((noinline))
static void wrapped_offset_source_overread(void) {
    char source[24] = {0};
    output_offset_outer(source, 9);
}

__attribute__((noinline))
static ssize_t negative_offset_wrapper(char *destination, size_t count) {
    return read(STDIN_FILENO, destination - 1, count);
}

__attribute__((noinline))
static void wrapped_negative_offset_underflow(void) {
    char destination[32];
    negative_offset_wrapper(destination, 1);
}

__attribute__((noinline))
static void release_wrapper(char *pointer) {
    free(pointer);
}

__attribute__((noinline))
static void wrapped_use_after_free(void) {
    char *buffer = malloc(32);
    release_wrapper(buffer);
    puts(buffer);
}

__attribute__((noinline))
static void mmap_overflow(void) {
    char *mapping = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping != MAP_FAILED) {
        read(STDIN_FILENO, mapping, 0x20000);
        munmap(mapping, 0x10000);
    }
}

typedef struct callback_object {
    void (*callback)(const char *message);
    char message[24];
} callback_object;

static callback_object *callback_slots[2];

__attribute__((noinline))
static void print_callback(const char *message) {
    puts(message);
}

__attribute__((noinline))
static void create_callback_slot(unsigned int index) {
    callback_object *object = calloc(1, sizeof(*object));
    if (object != NULL && index < 2) {
        object->callback = print_callback;
        callback_slots[index] = object;
    }
}

__attribute__((noinline))
static void delete_callback_slot(unsigned int index) {
    if (index < 2 && callback_slots[index] != NULL) {
        free(callback_slots[index]);
    }
}

__attribute__((noinline))
static void trigger_callback_slot(unsigned int index) {
    if (index < 2 && callback_slots[index] != NULL) {
        callback_slots[index]->callback(callback_slots[index]->message);
    }
}

__attribute__((noinline))
static void integer_truncation(void) {
    char text[24];
    char buffer[32];
    read(STDIN_FILENO, text, sizeof(text));
    unsigned long wide = strtoul(text, NULL, 10);
    unsigned short count = (unsigned short)wide;
    read(STDIN_FILENO, buffer, count);
}

__attribute__((noinline))
static void allocation_multiplication(void) {
    char text[24];
    read(STDIN_FILENO, text, sizeof(text));
    size_t count = strtoul(text, NULL, 10);
    char *buffer = malloc(count * 16);
    if (buffer != NULL) {
        free(buffer);
    }
}

__attribute__((noinline))
static void safe_narrow_calloc_product(void) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    char *buffer = calloc(count, 16U);
    if (buffer != NULL) {
        free(buffer);
    }
}

__attribute__((noinline))
static void unchecked_io_length_product(char *destination) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    read(STDIN_FILENO, destination, count * 16U);
}

__attribute__((noinline))
static void safe_wide_io_length_product(char *destination) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    read(STDIN_FILENO, destination, (size_t)count * 16U);
}

__attribute__((noinline))
static void unchecked_io_length_shift(char *destination) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    read(STDIN_FILENO, destination, count << 4U);
}

__attribute__((noinline))
static void safe_wide_io_length_shift(char *destination) {
    unsigned int count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    read(STDIN_FILENO, destination, (size_t)count << 4U);
}

__attribute__((noinline))
static void unchecked_dynamic_io_length_shift(char *destination) {
    unsigned int count;
    unsigned int shift;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    if (read(STDIN_FILENO, &shift, sizeof(shift)) != sizeof(shift)) {
        return;
    }
    read(STDIN_FILENO, destination, count << shift);
}

__attribute__((noinline))
static void safe_wide_dynamic_io_length_shift(char *destination) {
    unsigned int count;
    unsigned int shift;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    if (read(STDIN_FILENO, &shift, sizeof(shift)) != sizeof(shift)) {
        return;
    }
    if (shift > 4U) {
        return;
    }
    read(STDIN_FILENO, destination, (size_t)count << shift);
}

__attribute__((noinline))
static void safe_guarded_signed_io_product(char *destination) {
    long count;
    if (read(STDIN_FILENO, &count, sizeof(count)) != sizeof(count)) {
        return;
    }
    if (count <= 0 || count > 1024) {
        return;
    }
    read(STDIN_FILENO, destination, count * 16);
}

__attribute__((noinline))
static void negative_index(void) {
    char buffer[32] = {0};
    int index;
    scanf("%d", &index);
    if (index < 32) {
        buffer[index] = 'A';
    }
    puts(buffer);
}

__attribute__((noinline))
static void else_guarded_store(unsigned int index) {
    volatile unsigned char buffer[32] = {0};
    if (index >= sizeof(buffer)) {
        buffer[0] = '!';
    } else {
        buffer[index] = 'A';
    }
    write(STDOUT_FILENO, (const void *)buffer, 1);
}

__attribute__((noinline))
static void short_circuit_guarded_read(void) {
    unsigned int size;
    volatile unsigned char buffer[32] = {0};
    if (read(STDIN_FILENO, &size, sizeof(size)) != sizeof(size)) {
        return;
    }
    if (size <= sizeof(buffer)
        && read(STDIN_FILENO, (void *)buffer, size) > 0) {
        write(STDOUT_FILENO, (const void *)buffer, 1);
    }
}

__attribute__((noinline))
static void compound_guard_redefinition(void) {
    unsigned int index;
    volatile unsigned char buffer[32] = {0};
    if (read(STDIN_FILENO, &index, sizeof(index)) != sizeof(index)) {
        return;
    }
    if (index < sizeof(buffer)) {
        index += sizeof(buffer);
        buffer[index] = 'A';
    }
    write(STDOUT_FILENO, (const void *)buffer, 1);
}

__attribute__((noinline))
static ssize_t error_return_reader(char *destination, size_t limit) {
    return read(STDIN_FILENO, destination, limit);
}

__attribute__((noinline))
static void *error_return_allocator(size_t size) {
    return malloc(size);
}

__attribute__((noinline))
static void error_count_output(
    size_t *output,
    char *destination,
    size_t limit
) {
    *output = (size_t)error_return_reader(destination, limit);
}

__attribute__((noinline))
static void error_count_output_outer(
    size_t *output,
    char *destination,
    size_t limit
) {
    error_count_output(output, destination, limit);
}

__attribute__((noinline))
static int error_count_status_output(
    size_t *output,
    char *destination,
    size_t limit
) {
    error_count_output_outer(output, destination, limit);
    if (*output == SIZE_MAX) {
        return -1;
    }
    return 0;
}

__attribute__((noinline))
static int error_count_status_outer(
    size_t *output,
    char *destination,
    size_t limit
) {
    return error_count_status_output(output, destination, limit);
}

__attribute__((noinline))
static int error_count_ternary_status(
    size_t *output,
    char *destination,
    size_t limit
) {
    int status = error_count_status_outer(output, destination, limit);
    return status < 0 ? -7 : 0;
}

__attribute__((noinline))
static int error_count_boolean_status(
    size_t *output,
    char *destination,
    size_t limit
) {
    int status = error_count_status_outer(output, destination, limit);
    return status < 0;
}

__attribute__((noinline))
static int error_count_phi_status(
    size_t *output,
    char *destination,
    size_t limit
) {
    int status = error_count_status_outer(output, destination, limit);
    if (status < 0) {
        relational_status_sink = -11;
    } else {
        relational_status_sink = 0;
    }
    return relational_status_sink;
}

__attribute__((noinline))
static int error_count_unknown_phi_status(
    size_t *output,
    char *destination,
    size_t limit,
    int selector
) {
    error_count_output_outer(output, destination, limit);
    if (selector) {
        relational_status_sink = -13;
    } else {
        relational_status_sink = -17;
    }
    return relational_status_sink;
}

__attribute__((noinline))
static void error_output_overwritten(
    size_t *output,
    char *destination,
    size_t limit
) {
    error_count_output_outer(output, destination, limit);
    memset(output, 0, sizeof(*output));
}

__attribute__((noinline))
static void dynamic_output_memset(size_t *output, size_t overwrite_length) {
    memset(output, 0, overwrite_length);
}

__attribute__((noinline))
static ssize_t zero_capable_output_read(size_t *output) {
    return read(STDIN_FILENO, output, sizeof(*output));
}

__attribute__((noinline))
static void error_output_direct_read_may_not_write(
    size_t *output,
    char *destination,
    size_t limit
) {
    error_count_output_outer(output, destination, limit);
    read(STDIN_FILENO, output, sizeof(*output));
}

__attribute__((noinline))
static void error_output_nested_read_may_not_write(
    size_t *output,
    char *destination,
    size_t limit
) {
    error_count_output_outer(output, destination, limit);
    zero_capable_output_read(output);
}

__attribute__((noinline))
static void error_output_dynamic_unproven(
    size_t *output,
    char *destination,
    size_t limit,
    size_t overwrite_length
) {
    error_count_output_outer(output, destination, limit);
    dynamic_output_memset(output, overwrite_length);
}

__attribute__((noinline))
static void error_output_dynamic_bounded(
    size_t *output,
    char *destination,
    size_t limit,
    size_t overwrite_length
) {
    error_count_output_outer(output, destination, limit);
    if (overwrite_length >= sizeof(*output)) {
        dynamic_output_memset(output, overwrite_length);
    } else {
        dynamic_output_memset(output, sizeof(*output));
    }
}

__attribute__((noinline))
static void error_output_dynamic_after_reject(
    size_t *output,
    char *destination,
    size_t limit,
    size_t overwrite_length
) {
    error_count_output_outer(output, destination, limit);
    if (overwrite_length < sizeof(*output)) {
        dynamic_output_memset(output, sizeof(*output));
        comparison_sink ^= 0x31;
        return;
    }
    dynamic_output_memset(output, overwrite_length);
    comparison_sink ^= 0x32;
    relational_status_sink ^= 0x35;
    string_length_sink ^= overwrite_length;
    parsed_sink += (double)(overwrite_length & 1);
}

__attribute__((noinline))
static void error_output_dynamic_after_abort(
    size_t *output,
    char *destination,
    size_t limit,
    size_t overwrite_length
) {
    error_count_output_outer(output, destination, limit);
    if (overwrite_length < sizeof(*output)) {
        abort();
    }
    dynamic_output_memset(output, overwrite_length);
}

__attribute__((noinline))
static void error_output_dynamic_redefined_after_reject(
    size_t *output,
    char *destination,
    size_t limit,
    size_t overwrite_length
) {
    dynamic_length_sink = overwrite_length;
    error_count_output_outer(output, destination, limit);
    if (dynamic_length_sink < sizeof(*output)) {
        dynamic_output_memset(output, sizeof(*output));
        comparison_sink ^= 0x33;
        return;
    }
    dynamic_length_sink ^= (size_t)comparison_sink;
    dynamic_output_memset(output, dynamic_length_sink);
    comparison_sink ^= 0x34;
}

__attribute__((noinline))
static void error_output_dynamic_three_way(
    size_t *output,
    char *destination,
    size_t limit,
    size_t overwrite_length
) {
    error_count_output_outer(output, destination, limit);
    if (overwrite_length >= sizeof(*output)) {
        dynamic_output_memset(output, overwrite_length);
    } else if (overwrite_length != 0) {
        dynamic_output_memset(output, overwrite_length);
    } else {
        dynamic_output_memset(output, sizeof(*output));
    }
}

__attribute__((noinline))
static void error_output_readonly(
    size_t *output,
    char *destination,
    size_t limit
) {
    size_t peer = 0;
    error_count_output_outer(output, destination, limit);
    comparison_sink = memcmp(output, &peer, sizeof(peer));
}

__attribute__((noinline))
static void unchecked_error_result_allocation(void) {
    char buffer[32];
    error_result_size = (size_t)error_return_reader(buffer, sizeof(buffer));
    void *allocation = error_return_allocator(error_result_size);
    free(allocation);
}

__attribute__((noinline))
static void checked_error_result_allocation(void) {
    char buffer[32];
    error_result_size = (size_t)error_return_reader(buffer, sizeof(buffer));
    if (error_result_size == SIZE_MAX) {
        return;
    }
    void *allocation = error_return_allocator(error_result_size);
    free(allocation);
}

__attribute__((noinline))
static void unchecked_error_output_field_allocation(void) {
    char buffer[32];
    error_count_output_outer(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (error_output_record.status != SIZE_MAX) {
        void *allocation = error_return_allocator(
            error_output_record.count + 16
        );
        free(allocation);
    }
}

__attribute__((noinline))
static void checked_error_output_field_allocation(void) {
    char buffer[32];
    error_count_output_outer(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (error_output_record.count == SIZE_MAX) {
        return;
    }
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void unchecked_status_output_field_allocation(void) {
    char buffer[32];
    error_count_status_outer(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void checked_status_output_field_allocation(void) {
    char buffer[32];
    int status = error_count_status_outer(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (status != 0) {
        return;
    }
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void unchecked_ternary_status_output_allocation(void) {
    char buffer[32];
    error_count_ternary_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void checked_ternary_status_output_allocation(void) {
    char buffer[32];
    int status = error_count_ternary_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (status != 0) {
        return;
    }
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void nonnegative_ternary_status_output_allocation(void) {
    char buffer[32];
    int status = error_count_ternary_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (status >= 0) {
        void *allocation = error_return_allocator(
            error_output_record.count + 16
        );
        free(allocation);
    }
}

__attribute__((noinline))
static void unchecked_boolean_status_output_allocation(void) {
    char buffer[32];
    error_count_boolean_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void checked_boolean_status_output_allocation(void) {
    char buffer[32];
    int status = error_count_boolean_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (status != 0) {
        return;
    }
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void unchecked_phi_status_output_allocation(void) {
    char buffer[32];
    error_count_phi_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void checked_phi_status_output_allocation(void) {
    char buffer[32];
    int status = error_count_phi_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    if (status != 0) {
        return;
    }
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void unchecked_unknown_phi_status_output_allocation(int selector) {
    char buffer[32];
    error_count_unknown_phi_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        selector
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void checked_unknown_phi_status_output_allocation(int selector) {
    char buffer[32];
    int status = error_count_unknown_phi_status(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        selector
    );
    if (status != 0) {
        return;
    }
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void overwritten_error_output_allocation(void) {
    char buffer[32];
    error_output_overwritten(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void direct_read_may_not_write_allocation(void) {
    char buffer[32];
    error_output_direct_read_may_not_write(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void nested_read_may_not_write_allocation(void) {
    char buffer[32];
    error_output_nested_read_may_not_write(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void unproven_dynamic_error_output_allocation(size_t overwrite_length) {
    char buffer[32];
    error_output_dynamic_unproven(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        overwrite_length
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void bounded_dynamic_error_output_allocation(size_t overwrite_length) {
    char buffer[32];
    error_output_dynamic_bounded(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        overwrite_length
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void accepted_dynamic_error_output_allocation(size_t overwrite_length) {
    char buffer[32];
    error_output_dynamic_after_reject(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        overwrite_length
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void terminating_dynamic_error_output_allocation(size_t overwrite_length) {
    char buffer[32];
    error_output_dynamic_after_abort(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        overwrite_length
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void redefined_dynamic_error_output_allocation(size_t overwrite_length) {
    char buffer[32];
    error_output_dynamic_redefined_after_reject(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        overwrite_length
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void three_way_dynamic_error_output_allocation(size_t overwrite_length) {
    char buffer[32];
    error_output_dynamic_three_way(
        &error_output_record.count,
        buffer,
        sizeof(buffer),
        overwrite_length
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

__attribute__((noinline))
static void readonly_error_output_allocation(void) {
    char buffer[32];
    error_output_readonly(
        &error_output_record.count,
        buffer,
        sizeof(buffer)
    );
    void *allocation = error_return_allocator(error_output_record.count + 16);
    free(allocation);
}

int main(int argc, char **argv) {
    if (argc == 2) {
        format_string();
        unterminated_printf_argument();
        wrapped_unterminated_printf_argument();
        bounded_printf_argument();
        oversized_precision_printf_argument();
        oversized_strnlen();
        wrapped_oversized_strnlen();
        bounded_strnlen_exact();
        oversized_strncmp();
        short_peer_strncmp();
        unsafe_dynamic_precision_printf_argument();
        guarded_dynamic_precision_printf_argument();
        stack_overflow();
        scanf_overflow();
        heap_overflow();
        dynamic_heap_off_by_one();
        dynamic_heap_source_overread();
        wrapped_dynamic_heap_source_overread();
        short_read_tail_leak();
        checked_full_read_output();
        allocation_addition_wrap();
        checked_allocation_addition();
        scalar_allocation_summary_overflow();
        scalar_allocation_capacity_overflow();
        scalar_allocation_capacity_exact();
        bounded_read_result_allocation();
        checked_calloc_implicit_product();
        reallocarray_off_by_one();
        safe_reallocarray_fill();
        aligned_alloc_overflow();
        fortified_copy_source_overread();
        active_fortified_copy_abort();
        disabled_fortified_copy_overflow();
        wrapped_fortified_read_unterminated();
        active_fortified_read_abort();
        active_fortified_strncpy_abort();
        disabled_fortified_strncpy_overflow();
        fortified_strncpy_source_overread();
        fortified_strncpy_unterminated_destination();
        isoc23_scanf_length();
        memcmp_first_source_overread();
        memcmp_second_source_overread();
        wrapped_memcmp_source_overread();
        safe_memcmp_exact();
        memchr_source_overread();
        memchr_exact_source();
        bcmp_first_source_overread();
        writev_first_source_overread();
        writev_exact_source();
        writev_iovec_array_overread();
        writev_second_source_overread();
        wrapped_writev_source_overread();
        readv_first_destination_overflow();
        readv_exact_destination();
        readv_iovec_array_overread();
        readv_second_destination_overflow();
        wrapped_readv_destination_overflow();
        readv_unterminated_printf();
        sendmsg_payload_source_overread();
        sendmsg_control_source_overread();
        sendmsg_exact_source();
        sendmsg_header_overread();
        recvmsg_payload_destination_overflow();
        wrapped_recvmsg_destination_overflow();
        recvmsg_unterminated_printf();
        stateful_strtok_format();
        unterminated_strtok_input();
        clean_strtok_reset();
        strtod_length();
        unterminated_strtod_input();
        constant_strtod_length();
        unterminated_strcpy_source();
        terminated_strcpy_source();
        active_fortified_strcpy_abort();
        disabled_fortified_strcpy_overflow();
        active_fortified_sprintf_abort();
        disabled_fortified_sprintf_overflow();
        fortified_sprintf_unterminated_source();
        use_after_free();
        wrapped_stack_overflow();
        wrapped_scalar_length_overflow();
        wrapped_scalar_length_exact();
        wrapped_offset_destination_overflow();
        wrapped_offset_destination_exact();
        wrapped_offset_source_overread();
        wrapped_negative_offset_underflow();
        wrapped_use_after_free();
        mmap_overflow();
        create_callback_slot(0);
        delete_callback_slot(0);
        trigger_callback_slot(0);
        integer_truncation();
        allocation_multiplication();
        safe_narrow_calloc_product();
        unchecked_io_length_product((char *)argv);
        safe_wide_io_length_product((char *)argv);
        unchecked_io_length_shift((char *)argv);
        safe_wide_io_length_shift((char *)argv);
        unchecked_dynamic_io_length_shift((char *)argv);
        safe_wide_dynamic_io_length_shift((char *)argv);
        safe_guarded_signed_io_product((char *)argv);
        negative_index();
        else_guarded_store((unsigned int)argc);
        short_circuit_guarded_read();
        compound_guard_redefinition();
        unchecked_error_result_allocation();
        checked_error_result_allocation();
        unchecked_error_output_field_allocation();
        checked_error_output_field_allocation();
        unchecked_status_output_field_allocation();
        checked_status_output_field_allocation();
        unchecked_ternary_status_output_allocation();
        checked_ternary_status_output_allocation();
        nonnegative_ternary_status_output_allocation();
        unchecked_boolean_status_output_allocation();
        checked_boolean_status_output_allocation();
        unchecked_phi_status_output_allocation();
        checked_phi_status_output_allocation();
        unchecked_unknown_phi_status_output_allocation(argc);
        checked_unknown_phi_status_output_allocation(argc);
        overwritten_error_output_allocation();
        direct_read_may_not_write_allocation();
        nested_read_may_not_write_allocation();
        unproven_dynamic_error_output_allocation((size_t)argc - 2);
        bounded_dynamic_error_output_allocation((size_t)argc - 2);
        accepted_dynamic_error_output_allocation((size_t)argc - 2);
        terminating_dynamic_error_output_allocation((size_t)argc - 2);
        redefined_dynamic_error_output_allocation((size_t)argc - 2);
        three_way_dynamic_error_output_allocation((size_t)argc - 2);
        readonly_error_output_allocation();
    }
    return argv == NULL;
}
