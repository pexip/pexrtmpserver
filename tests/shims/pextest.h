/* PexRTMPServer test-suite compatibility shim.
 *
 * The pexrtmpserver test-suite is kept in sync with the copy living in the
 * (private) pexip/media repository.  Over there a couple of small helper
 * macros live in "pextest.h".  None of them require anything that is not
 * already provided by the upstream GStreamer check library, so this shim
 * simply maps the PEX_* helpers onto their upstream GST_* equivalents.  This
 * lets the very same test sources build & run against a plain upstream
 * GStreamer installation.
 */

#ifndef __PEXTEST_H__
#define __PEXTEST_H__

#include <gst/check/gstcheck.h>

G_BEGIN_DECLS

/* In pexip/media this variant additionally silences the GStreamer state-change
 * warnings that some of the (deliberately abusive) stress tests provoke.  The
 * only tests using it are flagged as "broken" in the suite and therefore never
 * actually run, so mapping it to the plain GST_START_TEST is sufficient. */
#ifndef PEX_START_TEST_IGNORE_STATECHANGE_WARNINGS
#define PEX_START_TEST_IGNORE_STATECHANGE_WARNINGS(name) GST_START_TEST (name)
#endif

#ifndef PEX_END_TEST
#define PEX_END_TEST GST_END_TEST
#endif

/* Skip helpers used inside test bodies in the pexip/media copy. On the
 * platforms/build configurations the suite actually runs in (non-MSVC, shared
 * build) these are no-ops; elsewhere they bail out of the test early. */
#if defined(_MSC_VER)
#define SKIP_BROKEN_TEST_IF_MSVC return
#else
#define SKIP_BROKEN_TEST_IF_MSVC do { } while (0)
#endif

#if defined(PEX_RTMP_SERVER_STATIC_BUILD)
#define SKIP_BROKEN_TEST_IF_STATIC_BUILD return
#else
#define SKIP_BROKEN_TEST_IF_STATIC_BUILD do { } while (0)
#endif

/* Plain test runner main(). */
#ifndef PEX_CHECK_MAIN
#define PEX_CHECK_MAIN(name) GST_CHECK_MAIN (name)
#endif

/* Test runner main() that makes sure an environment variable is set before the
 * suite is run (used here to pick a sensible default GST_DEBUG level). */
#ifndef PEX_CHECK_MAIN_WITH_ENV
#define PEX_CHECK_MAIN_WITH_ENV(name, env_var, env_val)         \
int main (int argc, char **argv)                                \
{                                                               \
  Suite *s;                                                     \
  g_setenv ((env_var), (env_val), FALSE);                       \
  gst_check_init (&argc, &argv);                                \
  s = name ## _suite ();                                        \
  return gst_check_run_suite (s, # name, __FILE__);             \
}
#endif

G_END_DECLS

#endif /* __PEXTEST_H__ */
