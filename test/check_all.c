#include <stdlib.h>
#include <check.h>
#include "check_all.h"


int main(int argc, char **argv) {
    int number_failed;

    SRunner *sr;
    sr = srunner_create(session_suite());
    //srunner_add_suite(sr, next_suite());


    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
