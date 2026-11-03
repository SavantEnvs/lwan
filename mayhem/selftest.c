/*
 * Known-answer tests for liblwan, run by mayhem/test.sh. Each check prints "PASS <name>" or
 * "FAIL <name>"; the process exits non-zero if any check fails. Linking a non-NDEBUG liblwan also
 * runs upstream's LWAN_SELF_TEST() constructors (hash, config, coro, request, response, tables)
 * before main().
 *
 * The upstream HTTP suite (src/scripts/testsuite.py) needs Landlock, which lwan's serve_files module
 * requires and many kernels/sandboxes lack, so it cannot serve as the oracle here.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lwan-private.h"
#include "lwan-config.h"
#include "lwan-strbuf.h"
#include "lwan-template.h"
#include "base64.h"
#include "hash.h"
#include "int-to-str.h"
#include "patterns.h"

static int n_failed;

#define CHECK(name, cond)                                                      \
    do {                                                                       \
        if (cond) {                                                            \
            printf("PASS %s\n", name);                                         \
        } else {                                                               \
            printf("FAIL %s\n", name);                                         \
            n_failed++;                                                        \
        }                                                                      \
    } while (0)

static void test_base64(void)
{
    const char *plain = "Hello, lwan!";
    size_t len = 0;
    unsigned char *enc = base64_encode((const unsigned char *)plain, strlen(plain), &len);
    CHECK("base64_encode", enc && len == 16 && !memcmp(enc, "SGVsbG8sIGx3YW4h", 16));

    size_t dlen = 0;
    unsigned char *dec = enc ? base64_decode(enc, len, &dlen) : NULL;
    CHECK("base64_decode", dec && dlen == strlen(plain) && !memcmp(dec, plain, dlen));
    free(enc);
    free(dec);

    CHECK("base64_validate_ok", base64_validate((const unsigned char *)"Zm9vYg==", 8));
    CHECK("base64_validate_bad", !base64_validate((const unsigned char *)"Zm9v*g==", 8));
    CHECK("base64_encoded_len", base64_encoded_len(5) == 8);
}

static void test_int_to_str(void)
{
    char buf[INT_TO_STR_BUFFER_SIZE];
    size_t len;
    char *s;

    s = int_to_string(-12345, buf, &len);
    CHECK("int_to_string_negative", len == 6 && !strcmp(s, "-12345"));
    s = uint_to_string(0, buf, &len);
    CHECK("uint_to_string_zero", len == 1 && !strcmp(s, "0"));
    s = uint_to_string(1234567890123ULL, buf, &len);
    CHECK("uint_to_string_large", len == 13 && !strcmp(s, "1234567890123"));
    CHECK("uint_to_string_2_digits", !strncmp(uint_to_string_2_digits(7), "07", 2));
}

static void test_strbuf(void)
{
    struct lwan_strbuf sb;
    CHECK("strbuf_init", lwan_strbuf_init(&sb));
    lwan_strbuf_append_strz(&sb, "abc");
    lwan_strbuf_append_char(&sb, '-');
    lwan_strbuf_append_printf(&sb, "%d:%s", 42, "xyz");
    CHECK("strbuf_append", lwan_strbuf_get_length(&sb) == 10 &&
                               !strcmp(lwan_strbuf_get_buffer(&sb), "abc-42:xyz"));
    lwan_strbuf_reset(&sb);
    CHECK("strbuf_reset", lwan_strbuf_get_length(&sb) == 0);
    lwan_strbuf_setz(&sb, "replaced");
    CHECK("strbuf_set", !strcmp(lwan_strbuf_get_buffer(&sb), "replaced"));
    lwan_strbuf_free(&sb);
}

static void test_parsers(void)
{
    CHECK("parse_long", parse_long("123456", -1) == 123456);
    CHECK("parse_long_default", parse_long("12x", -1) == -1);
    CHECK("parse_int_negative", parse_int("-77", 0) == -77);
    CHECK("parse_int_overflow_default", parse_int("99999999999999", 5) == 5);
    CHECK("parse_bool_true", parse_bool("true", false) == true);
    CHECK("parse_bool_off", parse_bool("off", true) == false);
    CHECK("parse_bool_default", parse_bool("maybe", true) == true);
    CHECK("parse_time_period_hm", parse_time_period("1h 30m", 0) == 5400);
    CHECK("parse_time_period_days", parse_time_period("2d", 0) == 172800);
    CHECK("parse_time_period_invalid", parse_time_period("10", 99) == 99);
}

static void test_config(void)
{
    char path[] = "/tmp/lwan-selftest-XXXXXX";
    int fd = mkstemp(path);
    CHECK("config_tmpfile", fd >= 0);
    if (fd < 0)
        return;

    const char *conf = "top = value one\n"
                       "# a comment\n"
                       "section arg {\n"
                       "    inner = 42\n"
                       "    nested {\n"
                       "        deep = yes\n"
                       "    }\n"
                       "}\n"
                       "last = done\n";
    ssize_t w = write(fd, conf, strlen(conf));
    close(fd);
    CHECK("config_write", w == (ssize_t)strlen(conf));

    struct config *c = config_open(path);
    CHECK("config_open", c != NULL);
    if (!c) {
        unlink(path);
        return;
    }

    const struct config_line *l;
    l = config_read_line(c);
    CHECK("config_line_kv", l && l->type == CONFIG_LINE_TYPE_LINE && !strcmp(l->key, "top") &&
                                !strcmp(l->value, "value one"));
    l = config_read_line(c);
    CHECK("config_section_start", l && l->type == CONFIG_LINE_TYPE_SECTION &&
                                      !strcmp(l->key, "section") && !strcmp(l->value, "arg"));
    l = config_read_line(c);
    CHECK("config_inner_kv", l && l->type == CONFIG_LINE_TYPE_LINE && !strcmp(l->key, "inner") &&
                                 parse_int(l->value, 0) == 42);
    l = config_read_line(c);
    CHECK("config_nested_section", l && l->type == CONFIG_LINE_TYPE_SECTION && !strcmp(l->key, "nested"));
    l = config_read_line(c);
    CHECK("config_deep_kv", l && l->type == CONFIG_LINE_TYPE_LINE && !strcmp(l->key, "deep") &&
                                parse_bool(l->value, false));
    l = config_read_line(c);
    CHECK("config_nested_end", l && l->type == CONFIG_LINE_TYPE_SECTION_END);
    l = config_read_line(c);
    CHECK("config_section_end", l && l->type == CONFIG_LINE_TYPE_SECTION_END);
    l = config_read_line(c);
    CHECK("config_last_kv", l && l->type == CONFIG_LINE_TYPE_LINE && !strcmp(l->key, "last") &&
                                !strcmp(l->value, "done"));
    l = config_read_line(c);
    CHECK("config_eof", l == NULL && config_last_error(c) == NULL);
    config_close(c);
    unlink(path);
}

struct tpl_vars {
    char *name;
    char *markup;
    int count;
};

#undef TPL_STRUCT
#define TPL_STRUCT struct tpl_vars
static const struct lwan_var_descriptor tpl_desc[] = {
    TPL_VAR_STR(name),
    TPL_VAR_STR_ESCAPE(markup),
    TPL_VAR_INT(count),
    TPL_VAR_SENTINEL,
};

static void test_template(void)
{
    struct lwan_tpl *tpl =
        lwan_tpl_compile_string("Hello {{name}}! n={{count}} m={{markup}}.", tpl_desc);
    CHECK("template_compile", tpl != NULL);
    if (!tpl)
        return;

    struct tpl_vars v = {.name = "World", .markup = "<b>&\"x\"</b>", .count = 42};
    struct lwan_strbuf *out = lwan_tpl_apply(tpl, &v);
    CHECK("template_apply", out && !strcmp(lwan_strbuf_get_buffer(out),
                                           "Hello World! n=42 m=&lt;b&gt;&amp;&quot;x&quot;&lt;&#x2f;b&gt;."));
    lwan_strbuf_free(out);

    v.count = -7;
    v.name = "again";
    out = lwan_tpl_apply(tpl, &v);
    CHECK("template_reapply", out && !strncmp(lwan_strbuf_get_buffer(out), "Hello again! n=-7 ", 18));
    lwan_strbuf_free(out);
    lwan_tpl_free(tpl);

}

static void test_hash(void)
{
    struct hash *h = hash_str_new(NULL, NULL);
    CHECK("hash_new", h != NULL);
    if (!h)
        return;
    hash_add(h, "alpha", "1");
    hash_add(h, "beta", "2");
    hash_add(h, "gamma", "3");
    CHECK("hash_count", hash_get_count(h) == 3);
    CHECK("hash_find", !strcmp(hash_find(h, "beta"), "2"));
    CHECK("hash_find_missing", hash_find(h, "delta") == NULL);
    CHECK("hash_del", hash_del(h, "beta") == 0 && hash_find(h, "beta") == NULL &&
                          hash_get_count(h) == 2);
    CHECK("hash_add_unique_dup", hash_add_unique(h, "alpha", "x") != 0);
    hash_unref(h);
}

static void test_tables(void)
{
    lwan_tables_init();
    CHECK("mime_html", !strcmp(lwan_determine_mime_type_for_file_name("index.html"), "text/html"));
    CHECK("mime_png", !strcmp(lwan_determine_mime_type_for_file_name("dir/pic.png"), "image/png"));
    CHECK("mime_js", !strcmp(lwan_determine_mime_type_for_file_name("app.js"), "text/javascript") ||
                         !strcmp(lwan_determine_mime_type_for_file_name("app.js"), "application/javascript"));
    CHECK("mime_unknown",
          !strcmp(lwan_determine_mime_type_for_file_name("file.nosuchext"), "application/octet-stream"));
    CHECK("status_ok", !strcmp(lwan_http_status_as_string(HTTP_OK), "OK"));
    CHECK("status_not_found",
          !strcmp(lwan_http_status_as_string(HTTP_NOT_FOUND), "Not found"));
    CHECK("status_code_string",
          !strncmp(lwan_http_status_as_string_with_code(HTTP_NOT_FOUND), "404 ", 4));
    lwan_tables_shutdown();
}

static void test_time(void)
{
    time_t t = 0;
    int r = lwan_parse_rfc_time("Fri, 09 Aug 2013 23:54:35 GMT", &t);
    CHECK("parse_rfc_time", r == 0 && t == 1376092475);

    char out[30];
    CHECK("format_rfc_time", lwan_format_rfc_time((time_t)1376092475, out) == 0 &&
                                 !strncmp(out, "Fri, 09 Aug 2013 23:54:35 GMT", 29));
    CHECK("parse_rfc_time_garbage", lwan_parse_rfc_time("not a date at all, definitely!", &t) != 0);
}

static void test_patterns(void)
{
    struct str_find sf[16];
    const char *err = NULL;
    const char *subject = "foo/123x456";
    int n = str_find(subject, "foo/(%d+)(%a)(%d+)", sf, 16, &err);
    CHECK("str_find_match", n == 4 && err == NULL);
    CHECK("str_find_group1", n == 4 && sf[1].sm_eo - sf[1].sm_so == 3 &&
                                 !strncmp(subject + sf[1].sm_so, "123", 3));
    CHECK("str_find_group2", n == 4 && !strncmp(subject + sf[2].sm_so, "x", 1));
    CHECK("str_find_group3", n == 4 && !strncmp(subject + sf[3].sm_so, "456", 3));
    CHECK("str_find_nomatch", str_find("bar/zzz", "foo/(%d+)", sf, 16, &err) == 0);
}

static void test_socket_address(void)
{
    char v4[] = "127.0.0.1:8080";
    char *node = NULL, *port = NULL;
    sa_family_t fam = lwan_socket_parse_address(v4, &node, &port);
    CHECK("socket_parse_ipv4", fam == AF_INET && node && port && !strcmp(node, "127.0.0.1") &&
                                   !strcmp(port, "8080"));

    char v6[] = "[::1]:9000";
    node = port = NULL;
    fam = lwan_socket_parse_address(v6, &node, &port);
    CHECK("socket_parse_ipv6", fam == AF_INET6 && node && port && !strcmp(node, "::1") &&
                                   !strcmp(port, "9000"));
}

int main(void)
{
    test_base64();
    test_int_to_str();
    test_strbuf();
    test_parsers();
    test_config();
    test_template();
    test_hash();
    test_tables();
    test_time();
    test_patterns();
    test_socket_address();
    fflush(stdout);
    return n_failed ? 1 : 0;
}
