/* Compatibility shim for the handful of helpers the test-suite uses from
 * pexip/media's "pex/tools/pextools.h".
 *
 * Only pex_testfile_path() is required by the rtmp test-suite.  It returns the
 * directory that holds the test data (certificates etc.).  We resolve it from
 * the PEX_TESTFILE_PATH environment variable when set (this lets the suite run
 * from any working directory), falling back to the compile-time TESTS_SRCDIR
 * that the build system points at the in-tree tests/ directory.
 */

#ifndef __PEX_SHIM_PEXTOOLS_H__
#define __PEX_SHIM_PEXTOOLS_H__

#include <glib.h>

G_BEGIN_DECLS

#ifndef TESTS_SRCDIR
#define TESTS_SRCDIR "."
#endif

static inline const gchar *
pex_testfile_path (const gchar * suffix)
{
  static gchar path[4096];
  const gchar *base = g_getenv ("PEX_TESTFILE_PATH");

  if (base == NULL || *base == '\0')
    base = TESTS_SRCDIR;

  g_snprintf (path, sizeof (path), "%s%s", base, suffix != NULL ? suffix : "");
  return path;
}

G_END_DECLS

#endif /* __PEX_SHIM_PEXTOOLS_H__ */
