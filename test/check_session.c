#include <stdlib.h>
#include <check.h>
#include "check_all.h"

static struct event_data *ev_data = NULL;

#define BYTEARR_NEW(str) bytearray_new_copy(str, strlen(str))

void test_cookie_remove_helper(char *cookie, char *expected,
        void (*runner)(char *, char *, int)) {
    /* Initialize */
    ev_data = init_event_data(CLIENT_LISTENER, 0, 0, false, false, HTTP_REQUEST,
            NULL);

    ev_data->cookie_header_value_ref = BYTEARR_NEW(cookie);

    extract_sessid_parse_cookie(ev_data->cookie_header_value_ref->data,
            ev_data->cookie_header_value_ref->len, ev_data);

    struct_array_add(ev_data->all_header_fields, BYTEARR_NEW("Cookie"));
    struct_array_add(ev_data->all_header_values,
            ev_data->cookie_header_value_ref);

    /* Run Test */
    runner(cookie, expected, (int) is_conn_cancelled(ev_data));

    /* Teardown */
    free_event_data(ev_data);
    ev_data = NULL;
}

void cookie_succeed_checks(char *cookie, char *expected, int is_cancelled) {
    ck_assert_msg(!is_cancelled,
            "extract_sessid_parse_cookie() should not cause a cancel");
    ck_assert_msg(remove_shim_sessid_cookie(ev_data) == 0,
            "remove_shim_sessid_cookie() did not return 0");
    ck_assert_msg(!is_conn_cancelled(ev_data),
            "session was cancelled unexpectedly");
    bytearray_nul_terminate(ev_data->cookie_header_value_ref);
    if (strcmp(ev_data->cookie_header_value_ref->data, expected) != 0) {
        printf("Actual cookie:   \"%s\"\n",
                ev_data->cookie_header_value_ref->data);
        printf("Expected cookie: \"%s\"\n", expected);
        ck_abort_msg("SESSID cookie removed incorrectly");
    }
}

void cookie_fail_checks(char *cookie, char *expected, int is_cancelled) {
    ck_assert_msg(!!is_cancelled,
                "extract_sessid_parse_cookie() should cause a cancel");
}

void test_cookie_remove_succeed_helper(char *cookie, char *expected) {
    test_cookie_remove_helper(cookie, expected, cookie_succeed_checks);
}

void test_cookie_remove_fail_helper(char *cookie) {
    test_cookie_remove_helper(cookie, NULL, cookie_fail_checks);
}

START_TEST(test_cookie_remove_pass1) {
    test_cookie_remove_succeed_helper(
            "SHIM_SESSID=A979794BECFB45EEEE2D; langSetFlag=0; "
            "language=English; SID=obswlnshrzbrxhed",
            "langSetFlag=0; language=English; SID=obswlnshrzbrxhed");
}
END_TEST

START_TEST(test_cookie_remove_pass2) {
    test_cookie_remove_succeed_helper(
            "SHIM_SESSID=\"A979794BECFB45EEEE2D\"; langSetFlag=\"0\"; "
            "language=\"English\"; SID=\"obswlnshrzbrxhed\"",
            "langSetFlag=0; language=English; SID=obswlnshrzbrxhed");
}
END_TEST

START_TEST(test_cookie_remove_pass3) {
    test_cookie_remove_succeed_helper(
            "SHIM_SESSID=\"A979794BECFB45EEEE2D\"; a=1; b=; \t   c",
            "a=1; b; c");
}
END_TEST

START_TEST(test_cookie_remove_fail1) {
    test_cookie_remove_fail_helper(
            "a=\"1; b=2; c=3");
}
END_TEST

START_TEST(test_cookie_remove_fail2) {
    test_cookie_remove_fail_helper(
            "=1; b=2; c=3");
}
END_TEST

Suite *session_suite() {
    Suite *s = suite_create("Session");

    TCase *tc_sess_cookie = tcase_create("Session Cookie remove");
    tcase_add_test(tc_sess_cookie, test_cookie_remove_pass1);
    tcase_add_test(tc_sess_cookie, test_cookie_remove_pass2);
    tcase_add_test(tc_sess_cookie, test_cookie_remove_pass3);
    tcase_add_test(tc_sess_cookie, test_cookie_remove_fail1);
    tcase_add_test(tc_sess_cookie, test_cookie_remove_fail2);

    suite_add_tcase(s, tc_sess_cookie);

    return s;
}
