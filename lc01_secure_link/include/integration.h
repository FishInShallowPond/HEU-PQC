#ifndef LC_INTEGRATION_H
#define LC_INTEGRATION_H

/* main dispatches here only for argv[1] == "--test-endpoint".
 * One process owns one software PQC device and one endpoint.
 * Returns a process exit code (0 means the requested test passed).
 */
int lc_integration_run(int argc, char **argv);

#endif
