#!/usr/bin/env python3

# Copyright (c) 2018 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

import collections
import sys
import subprocess
import re
import os
from email.utils import parseaddr
import logging
import argparse
from junitparser import TestCase, TestSuite, JUnitXml, Skipped, Error, Failure
from github import Github
from shutil import copyfile
import json
import tempfile
import traceback
import magic
import shlex
from pathlib import Path

# '*' makes it italic
EDIT_TIP = "\n\n*Tip: The bot edits this comment instead of posting a new " \
           "one, so you can check the comment's history to see earlier " \
           "messages.*"

logger = None


def git(*args):
    # Helper for running a Git command. Returns the rstrip()ed stdout output.
    # Called like git("diff"). Exits with SystemError (raised by sys.exit()) on
    # errors.

    git_cmd = ("git",) + args
    git_cmd_s = " ".join(shlex.quote(word) for word in git_cmd)  # For errors

    try:
        git_process = subprocess.Popen(
            git_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        sys.exit("git executable not found (when running '{}'). Check that "
                 "it's in listed in the PATH environment variable"
                 .format(git_cmd_s))
    except OSError as e:
        sys.exit("failed to run '{}': {}".format(git_cmd_s, e))

    stdout, stderr = git_process.communicate()
    if git_process.returncode or stderr:
        sys.exit("failed to run '{}': {}".format(
            git_cmd_s, stdout.decode("utf-8") + stderr.decode("utf-8")))

    return stdout.decode("utf-8").rstrip()


# This ends up as None when we're not running in a Zephyr tree
ZEPHYR_BASE = os.environ.get('ZEPHYR_BASE')

# The absolute path of the top-level git directory
GIT_TOP = git("rev-parse", "--show-toplevel")


def get_shas(refspec):
    # Returns the list of Git SHAs for 'refspec'

    return git('rev-list',
               '--max-count={}'.format(-1 if "." in refspec else 1),
               refspec).split()


class ComplianceTest:
    """
    Base class for tests. Inheriting classes should have a run() method and set
    these class variables:

      name:
        Test name

      doc:
        Link to documentation related to what's being tested

      path:
        The path the test runs in. This is just informative. The value is only
        used in messages.

      quote_fails:
        If True, failure output from the test will be put in a code block (```)
        in messages on GitHub
    """
    def __init__(self):
        self.fail_msg = ""
        self.info_msg = ""
        self.skip_msg = ""
        self.error_msg = ""

    def add_failure(self, msg):
        """
        Signals that the test failed, with message 'msg'. Can be called many
        times within the same test to report multiple failures.
        """
        if self.fail_msg:
            self.fail_msg += "\n\n"
        self.fail_msg += msg

    def add_info(self, msg):
        if self.info_msg:
            self.info_msg += "\n\n"
        self.info_msg += msg

    def error(self, msg):
        """
        Signals a problem with running the test, with message 'msg'.

        Raises an exception internally, so you do not need to put a 'return'
        after error().

        Any failures generated prior to the error() are included automatically
        in the message. Usually, any failures would indicate problems with the
        test code.
        """
        self.error_msg = msg
        raise EndTest

    def skip(self, msg):
        """
        Signals that the test should be skipped, with message 'msg'.

        Raises an exception internally, so you do not need to put a 'return'
        after skip().

        Any failures generated prior to the skip() are included automatically
        in the message. Usually, any failures would indicate problems with the
        test code.
        """
        self.skip_msg = msg
        raise EndTest

    def to_junit_testcase(self):
        """
        Returns a junitparser TestCase instance for the test. Should be called
        after the test has been run().
        """
        junit_testcase = TestCase(self.name)
        junit_testcase.classname = "Guidelines"

        if self.error_msg:
            junit_testcase.result = Error(self.error_msg, "error")
        elif self.fail_msg:
            failure = Failure(self.name + " issues", "failure")
            failure._elem.text = self.fail_msg
            junit_testcase.result = failure
        elif self.skip_msg:
            junit_testcase.result = Skipped(self.skip_msg, "skipped")

        return junit_testcase


class EndTest(Exception):
    """
    Raised by ComplianceTest.error()/skip() to end the test.

    Tests can raise EndTest themselves to immediately end the test, e.g. from
    within a nested function call.
    """


class CheckPatch(ComplianceTest):
    """
    Runs checkpatch and reports found issues
    """
    name = "checkpatch"
    doc = "https://docs.zephyrproject.org/latest/contribute/#coding-style"
    path = GIT_TOP
    quote_fails = True

    def run(self):
        # Default to Zephyr's checkpatch if ZEPHYR_BASE is set
        checkpatch = os.path.join(ZEPHYR_BASE or GIT_TOP, 'scripts',
                                  'checkpatch.pl')
        if not os.path.exists(checkpatch):
            self.skip(checkpatch + " not found")

        # git diff's output doesn't depend on the current (sub)directory
        diff = subprocess.Popen(('git', 'diff', commit_range),
                                stdout=subprocess.PIPE)
        try:
            subprocess.check_output((checkpatch, '--mailback', '--no-tree', '-'),
                                    stdin=diff.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True, cwd=GIT_TOP)

        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            if re.search("[1-9][0-9]* errors,", output):
                self.add_failure(output)


class KconfigCheck(ComplianceTest):
    """
    Checks is we are introducing any new warnings/errors with Kconfig,
    for example using undefiend Kconfig variables.
    """
    name = "Kconfig"
    doc = "https://docs.zephyrproject.org/latest/guides/kconfig/index.html"
    path = ZEPHYR_BASE
    quote_fails = True

    def run(self):
        kconf = self.parse_kconfig()

        self.check_top_menu_not_too_long(kconf)
        self.check_no_undef_within_kconfig(kconf)
        self.check_no_undef_outside_kconfig(kconf)

    def get_modules(self, modules_file):
        """
        Get a list of modules and put them in a file that is parsed by
        Kconfig

        This is needed to complete Kconfig sanity tests.

        """
        # Invoke the script directly using the Python executable since this is
        # not a module nor a pip-installed Python utility
        zephyr_module_path = os.path.join(ZEPHYR_BASE, "scripts",
                                          "zephyr_module.py")
        cmd = [sys.executable, zephyr_module_path,
               '--kconfig-out', modules_file]
        try:
            _ = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as ex:
            self.error(ex.output)

    def parse_kconfig(self):
        """
        Returns a kconfiglib.Kconfig object for the Kconfig files. We reuse
        this object for all tests to avoid having to reparse for each test.
        """
        if not ZEPHYR_BASE:
            self.skip("Not a Zephyr tree (ZEPHYR_BASE unset)")

        # Put the Kconfiglib path first to make sure no local Kconfiglib version is
        # used
        kconfig_path = os.path.join(ZEPHYR_BASE, "scripts", "kconfig")
        if not os.path.exists(kconfig_path):
            self.error(kconfig_path + " not found")

        sys.path.insert(0, kconfig_path)
        import kconfiglib

        # Look up Kconfig files relative to ZEPHYR_BASE
        os.environ["srctree"] = ZEPHYR_BASE

        # Parse the entire Kconfig tree, to make sure we see all symbols
        os.environ["SOC_DIR"] = "soc/"
        os.environ["ARCH_DIR"] = "arch/"
        os.environ["BOARD_DIR"] = "boards/*/*"
        os.environ["ARCH"] = "*"
        os.environ["CMAKE_BINARY_DIR"] = tempfile.gettempdir()
        os.environ['GENERATED_DTS_BOARD_CONF'] = "dummy"
        os.environ['DTS_POST_CPP'] = 'dummy'

        # For multi repo support
        self.get_modules(os.path.join(tempfile.gettempdir(), "Kconfig.modules"))

        # Tells Kconfiglib to generate warnings for all references to undefined
        # symbols within Kconfig files
        os.environ["KCONFIG_WARN_UNDEF"] = "y"

        try:
            # Note this will both print warnings to stderr _and_ return
            # them: so some warnings might get printed
            # twice. "warn_to_stderr=False" could unfortunately cause
            # some (other) warnings to never be printed.
            return kconfiglib.Kconfig()
        except kconfiglib.KconfigError as e:
            self.add_failure(str(e))
            raise EndTest

    def check_top_menu_not_too_long(self, kconf):
        """
        Checks that there aren't too many items in the top-level menu (which
        might be a sign that stuff accidentally got added there)
        """
        max_top_items = 50

        n_top_items = 0
        node = kconf.top_node.list
        while node:
            # Only count items with prompts. Other items will never be
            # shown in the menuconfig (outside show-all mode).
            if node.prompt:
                n_top_items += 1
            node = node.next

        if n_top_items > max_top_items:
            self.add_failure("""
Expected no more than {} potentially visible items (items with prompts) in the
top-level Kconfig menu, found {} items. If you're deliberately adding new
entries, then bump the 'max_top_items' variable in {}.
""".format(max_top_items, n_top_items, __file__))

    def check_no_undef_within_kconfig(self, kconf):
        """
        Checks that there are no references to undefined Kconfig symbols within
        the Kconfig files
        """
        undef_ref_warnings = "\n\n\n".join(warning for warning in kconf.warnings
                                           if "undefined symbol" in warning)

        if undef_ref_warnings:
            self.add_failure("Undefined Kconfig symbols:\n\n"
                             + undef_ref_warnings)

    def check_no_undef_outside_kconfig(self, kconf):
        """
        Checks that there are no references to undefined Kconfig symbols
        outside Kconfig files (any CONFIG_FOO where no FOO symbol exists)
        """
        # Grep for symbol references.
        #
        # Example output line for a reference to CONFIG_BAZ at line 17 of
        # foo/bar.c:
        #
        #   foo/bar.c<null>17<null>#ifdef CONFIG_BAZ
        #
        # 'git grep --only-matching' would get rid of the surrounding context
        # ('#ifdef '), but it was added fairly recently (second half of 2018),
        # so we extract the references from each line ourselves instead.
        #
        # The regex uses word boundaries (\b) to isolate the reference, and
        # negative lookahead to automatically whitelist the following:
        #
        #  - ##, for token pasting (CONFIG_FOO_##X)
        #
        #  - $, e.g. for CMake variable expansion (CONFIG_FOO_${VAR})
        #
        #  - @, e.g. for CMakes's configure_file() (CONFIG_FOO_@VAR@)
        #
        #  - {, e.g. for Python scripts ("CONFIG_FOO_{}_BAR".format(...)")
        #
        #  - *, meant for comments like '#endif /* CONFIG_FOO_* */
        #
        # We skip the samples/ and tests/ directories for now. They often
        # contain Kconfig files that are not part of the main Kconfig tree,
        # which will trigger false positives until we do something fancier.
        #
        # We also skip doc/releases, which often references removed symbols.

        # Warning: Needs to work with both --perl-regexp and the 're' module
        regex = r"\bCONFIG_[A-Z0-9_]+\b(?!\s*##|[$@{*])"

        grep_cmd = ["git", "grep", "--line-number", "-I", "--null",
                    "--perl-regexp", regex,
                    "--", ":!samples", ":!tests", ":!doc/releases"]

        grep_process = subprocess.Popen(grep_cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        cwd=ZEPHYR_BASE)

        grep_stdout, grep_stderr = grep_process.communicate()
        # Fail if there's anything on stderr too, so that it doesn't get missed
        if grep_process.returncode or grep_stderr:
            self.error("'{}' failed with exit code {} (while searching for "
                       "Kconfig symbol references)\n\nstdout:\n{}\n\n"
                       "stderr:\n{}"
                       .format(" ".join(grep_cmd), grep_process.returncode,
                               grep_stdout, grep_stderr))

        defined_syms = set(sym.name for sym in kconf.unique_defined_syms)
        undef_to_locs = collections.defaultdict(list)

        # splitlines() supports various line terminators
        for grep_line in grep_stdout.decode("utf-8").splitlines():
            path, lineno, line = grep_line.split("\0")

            # Extract symbol references (might be more than one) within the
            # line
            for sym_name in re.findall(regex, line):
                sym_name = sym_name[7:]  # Strip CONFIG_
                if sym_name not in defined_syms and \
                   sym_name not in UNDEF_KCONFIG_WHITELIST:

                    undef_to_locs[sym_name].append("{}:{}".format(path, lineno))

        if not undef_to_locs:
            return

        # String that describes all referenced but undefined Kconfig symbols,
        # in alphabetical order, along with the locations where they're
        # referenced. Example:
        #
        #   CONFIG_ALSO_MISSING    arch/xtensa/core/fatal.c:273
        #   CONFIG_MISSING         arch/xtensa/core/fatal.c:264, subsys/fb/cfb.c:20
        undef_desc = "\n".join(
            "CONFIG_{:35} {}".format(sym_name, ", ".join(locs))
            for sym_name, locs in sorted(undef_to_locs.items()))

        self.add_failure("""
Found references to undefined Kconfig symbols. If any of these are false
positives, then add them to UNDEF_KCONFIG_WHITELIST in {} in the ci-tools repo.

If the reference is for a comment like /* CONFIG_FOO_* */ (or
/* CONFIG_FOO_*_... */), then please use exactly that form (with the '*'). The
CI check knows not to flag it.

More generally, a reference followed by $, @, {{, *, or ## will never be
flagged.

{}""".format(os.path.basename(__file__), undef_desc))


# Many of these are symbols used as examples. Note that the list is sorted
# alphabetically, and skips the CONFIG_ prefix.
UNDEF_KCONFIG_WHITELIST = {
    "APP_LINK_WITH_",
    "CDC_ACM_PORT_NAME_",
    "CLOCK_STM32_SYSCLK_SRC_",
    "CMU",
    "COUNTER_RTC_STM32_CLOCK_SRC",
    "CRC",  # Used in TI CC13x2 / CC26x2 SDK comment
    "DEEP_SLEEP",  # #defined by RV32M1 in ext/
    "DESCRIPTION",
    "ERR",
    "ESP_DIF_LIBRARY",  # Referenced in CMake comment
    "EXPERIMENTAL",
    "FFT",  # Used as an example in cmake/extensions.cmake
    "FLAG",  # Used as an example
    "FOO",
    "FOO_LOG_LEVEL",
    "FOO_SETTING_1",
    "FOO_SETTING_2",
    "LIS2DW12_INT_PIN",
    "LSM6DSO_INT_PIN",
    "MODULES",
    "MYFEATURE",
    "MY_DRIVER_0",
    "NORMAL_SLEEP",  # #defined by RV32M1 in ext/
    "OPT",
    "OPT_0",
    "PEDO_THS_MIN",
    "REG1",
    "REG2",
    "SEL",
    "SHIFT",
    "SOC_WATCH",  # Issue 13749
    "SOME_BOOL",
    "SOME_INT",
    "SOME_OTHER_BOOL",
    "SOME_STRING",
    "STD_CPP",  # Referenced in CMake comment
    "TEST1",
    "TYPE_BOOLEAN",
    "USB_CONSOLE",
    "USE_STDC_",
    "WHATEVER",
}


class DeviceTreeCheck(ComplianceTest):
    """
    Runs the dtlib and edtlib test suites in scripts/dts/.
    """
    name = "Device tree"
    doc = "https://docs.zephyrproject.org/latest/guides/dts/index.html"
    quote_fails = True
    path = ZEPHYR_BASE

    def run(self):
        if not ZEPHYR_BASE:
            self.skip("Not a Zephyr tree (ZEPHYR_BASE unset)")

        # The dtlib/edtlib test suites rely on dictionaries preserving
        # insertion order. They don't before Python 3.6. The code could be
        # updated to use collections.OrderedDict to work around it, but I'm not
        # sure it's worth it with Python 3.6 starting to get old (released
        # December 2016).
        if sys.version_info < (3, 6, 0):
            self.skip("The dtlib/edtlib test suites require Python 3.6+")

        scripts_path = os.path.join(ZEPHYR_BASE, "scripts", "dts")

        sys.path.insert(0, scripts_path)
        import testdtlib
        import testedtlib

        # Hack: The test suites expect to be run from the scripts/dts
        # directory, because they compare repr() output that contains relative
        # paths against an expected string. Temporarily change the working
        # directory to scripts/dts/.
        #
        # Warning: This is not thread-safe, though the test suites run in a
        # fraction of a second.
        old_dir = os.getcwd()
        os.chdir(scripts_path)
        try:
            testdtlib.run()
            testedtlib.run()
        except SystemExit as e:
            # The dtlib and edtlib test suites call sys.exit() on failure,
            # which raises SystemExit. Let any errors in the test scripts
            # themselves trickle through and turn into an internal CI error.
            self.add_failure(str(e))
        finally:
            # Restore working directory
            os.chdir(old_dir)


class Codeowners(ComplianceTest):
    """
    Check if added files have an owner.
    """
    name = "Codeowners"
    doc = "https://help.github.com/articles/about-code-owners/"
    path = GIT_TOP
    quote_fails = True

    def ls_owned_files(self, codeowners):
        """Returns an OrderedDict mapping git patterns from the CODEOWNERS file
        to the corresponding list of files found on the filesystem.  It
        unfortunately does not seem possible to invoke git and re-use
        how 'git ignore' and/or 'git attributes' already implement this,
        we must re-invent it.
        """

        # TODO: filter out files not in "git ls-files" (e.g.,
        # sanity-out) _if_ the overhead isn't too high for a clean tree.
        #
        # pathlib.match() doesn't support **, so it looks like we can't
        # recursively glob the output of ls-files directly, only real
        # files :-(

        pattern2files = collections.OrderedDict()
        top_path = Path(GIT_TOP)

        with open(codeowners, "r") as codeo:
            for lineno, line in enumerate(codeo, start=1):

                if line.startswith("#") or not line.strip():
                    continue

                match = re.match(r"^([^\s,]+)\s+[^\s]+", line)
                if not match:
                    self.add_failure(
                        "Invalid CODEOWNERS line %d\n\t%s" %
                        (lineno, line))
                    continue

                git_patrn = match.group(1)
                glob = self.git_pattern_to_glob(git_patrn)
                files = []
                for abs_path in top_path.glob(glob):
                    # comparing strings is much faster later
                    files.append(str(abs_path.relative_to(top_path)))

                if not files:
                    self.add_failure("Path '{}' not found in the tree but is listed in "
                                     "CODEOWNERS".format(git_patrn))

                pattern2files[git_patrn] = files

        return pattern2files

    def git_pattern_to_glob(self, git_pattern):
        """Appends and prepends '**[/*]' when needed. Result has neither a
        leading nor a trailing slash.
        """

        if git_pattern.startswith("/"):
            ret = git_pattern[1:]
        else:
            ret = "**/" + git_pattern

        if git_pattern.endswith("/"):
            ret = ret + "**/*"
        elif os.path.isdir(os.path.join(GIT_TOP, ret)):
            self.add_failure("Expected '/' after directory '{}' "
                             "in CODEOWNERS".format(ret))

        return ret

    def run(self):
        # TODO: testing an old self.commit range that doesn't end
        # with HEAD is most likely a mistake. Should warn, see
        # https://github.com/zephyrproject-rtos/ci-tools/pull/24
        codeowners = os.path.join(GIT_TOP, "CODEOWNERS")
        if not os.path.exists(codeowners):
            self.skip("CODEOWNERS not available in this repo")

        name_changes = git("diff", "--name-only", "--diff-filter=ARCD",
                           commit_range)

        owners_changes = git("diff", "--name-only", commit_range, "--",
                             codeowners)

        if not name_changes and not owners_changes:
            # TODO: 1. decouple basic and cheap CODEOWNERS syntax
            # validation from the expensive ls_owned_files() scanning of
            # the entire tree. 2. run the former always.
            return

        logging.info("If this takes too long then cleanup and try again")
        patrn2files = self.ls_owned_files(codeowners)

        # The way git finds Renames and Copies is not "exact science",
        # however if one is missed then it will always be reported as an
        # Addition instead.
        new_files = git("diff", "--name-only", "--diff-filter=ARC",
                        commit_range).splitlines()
        logging.debug("New files %s", new_files)

        # Convert to pathlib.Path string representation (e.g.,
        # backslashes 'dir1\dir2\' on Windows) to be consistent
        # with self.ls_owned_files()
        new_files = [str(Path(f)) for f in new_files]

        new_not_owned = []
        for newf in new_files:
            f_is_owned = False

            for git_pat, owned in patrn2files.items():
                logging.debug("Scanning %s for %s", git_pat, newf)

                if newf in owned:
                    logging.info("%s matches new file %s", git_pat, newf)
                    f_is_owned = True
                    # Unlike github, we don't care about finding any
                    # more specific owner.
                    break

            if not f_is_owned:
                new_not_owned.append(newf)

        if new_not_owned:
            self.add_failure("New files added that are not covered in "
                             "CODEOWNERS:\n\n" + "\n".join(new_not_owned) +
                             "\n\nPlease add one or more entries in the "
                             "CODEOWNERS file to cover those files")


class Documentation(ComplianceTest):
    """
    Checks if documentation build has generated any new warnings.
    """
    name = "Documentation"
    doc = "https://docs.zephyrproject.org/latest/guides/documentation/index.html"
    path = os.getcwd()
    quote_fails = True

    def run(self):
        warnings_file = "doc.warnings"

        if os.path.exists(warnings_file) and os.path.getsize(warnings_file) > 0:
            with open(warnings_file, "r", encoding="utf-8") as docs_warning:
                self.add_failure(docs_warning.read())


class GitLint(ComplianceTest):
    """
    Runs gitlint on the commits and finds issues with style and syntax
    """
    name = "Gitlint"
    doc = "https://docs.zephyrproject.org/latest/contribute/#commit-guidelines"
    path = os.path.join(os.getcwd(), '[.gitlint]')
    quote_fails = False

    def run(self):
        # By default gitlint looks for .gitlint configuration only in
        # the current directory
        proc = subprocess.Popen(('gitlint', '--commits', commit_range),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                cwd=GIT_TOP)

        msg = ""
        if proc.wait() != 0:
            msg = proc.stdout.read()

        if msg != "":
            self.add_failure(msg.decode("utf-8"))


class PyLint(ComplianceTest):
    """
    Runs pylint on all .py files, with a limited set of checks enabled. The
    configuration is in the pylintrc file.
    """
    name = "pylint"
    doc = "https://www.pylint.org/"
    quote_fails = True
    path = ZEPHYR_BASE

    def run(self):
        # Path to pylint configuration file
        pylintrc = os.path.join(os.path.dirname(__file__), "pylintrc")

        # List of files added/modified by the commit(s).
        files = git(
            "diff", "--name-only", "--diff-filter=d", commit_range, "--",
            # Currently being overhauled. Will be checked later.
            ":!scripts/sanitycheck",
            # Skip to work around crash in pylint 2.2.2:
            # https://github.com/PyCQA/pylint/issues/2906
            ":!boards/xtensa/intel_s1000_crb/support/create_board_img.py") \
            .splitlines()

        # Filter out everything but Python files
        py_files = filter_py(files)
        if not py_files:
            return

        try:
            # Run pylint on added/modified Python files
            process = subprocess.Popen(
                ["pylint", "--rcfile=" + pylintrc] + py_files,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=ZEPHYR_BASE)
        except FileNotFoundError:
            self.error("pylint not found. Check that the directory it's in is "
                       "listed in the PATH environment variable.")
        except OSError as e:
            self.error("Failed to run pylint: " + str(e))

        stdout, stderr = process.communicate()
        if process.returncode or stderr:
            # Issues found, or a problem with pylint itself
            self.add_failure(stdout.decode("utf-8") + stderr.decode("utf-8"))


def filter_py(fnames):
    # PyLint check helper. Returns all Python script filenames among the
    # filenames in 'fnames'. Uses the python-magic library, so that we can
    # detect Python files that don't end in .py as well. python-magic is a
    # frontend to libmagic, which is also used by 'file'.

    return [fname for fname in fnames
            if fname.endswith(".py") or
               magic.from_file(fname, mime=True) == "text/x-python"]


class License(ComplianceTest):
    """
    Checks for licenses in new files added by the Pull request
    """
    name = "License"
    doc = "https://docs.zephyrproject.org/latest/contribute/#licensing"
    path = os.getcwd()
    quote_fails = False

    def run(self):
        # copyfile() below likely requires that getcwd()==GIT_TOP

        scancode = "/opt/scancode-toolkit/scancode"
        if not os.path.exists(scancode):
            self.skip("scancode-toolkit not installed")

        os.makedirs("scancode-files", exist_ok=True)
        # git diff's output doesn't depend on the current (sub)directory
        new_files = git("diff", "--name-only", "--diff-filter=A",
                        commit_range).splitlines()

        if not new_files:
            return

        for newf in new_files:
            file = str(newf).rstrip()
            os.makedirs(os.path.join('scancode-files',
                                     os.path.dirname(file)), exist_ok=True)
            copy = os.path.join("scancode-files", file)
            copyfile(file, copy)

        try:
            cmd = [scancode, '--verbose', '--copyright', '--license', '--license-diag', '--info',
                   '--classify', '--summary', '--html', 'scancode.html', '--json', 'scancode.json', 'scancode-files/']

            cmd_str = " ".join(cmd)
            logging.info(cmd_str)

            subprocess.check_output(cmd_str, stderr=subprocess.STDOUT,
                                    shell=True)

        except subprocess.CalledProcessError as ex:
            logging.error(ex.output)
            self.error("Exception when running scancode: " + str(ex))

        report = ""

        never_check_ext =  ['.yaml', '.html', '.rst', '.conf', '.cfg']
        never_check_langs = ['HTML']
        check_langs = ['CMake']
        with open('scancode.json', 'r') as json_fp:
            scancode_results = json.load(json_fp)
            for file in scancode_results['files']:
                if file['type'] == 'directory':
                    continue

                orig_path = str(file['path']).replace('scancode-files/', '')
                licenses = file['licenses']
                file_type = file.get("file_type")
                kconfig = "Kconfig" in orig_path and file_type in ['ASCII text']
                check = False

                if file.get("extension") in never_check_ext:
                    check = False
                elif file.get("programming_language") in never_check_langs:
                    check = False
                elif kconfig:
                    check = True
                elif file.get("programming_language") in check_langs:
                    check = True
                elif file.get("is_script"):
                    check = True
                elif file.get("is_source"):
                    check = True

                if check:
                    if not licenses:
                        report += ("* {} missing license.\n".format(orig_path))
                    else:
                        for lic in licenses:
                            if lic['key'] != "apache-2.0":
                                report += ("* {} is not apache-2.0 licensed: {}\n".format(
                                    orig_path, lic['key']))
                            if lic['category'] != 'Permissive':
                                report += ("* {} has non-permissive license: {}\n".format(
                                    orig_path, lic['key']))
                            if lic['key'] == 'unknown-spdx':
                                report += ("* {} has unknown SPDX: {}\n".format(
                                    orig_path, lic['key']))

                    if not file['copyrights'] and file.get("programming_language") != 'CMake':
                        report += ("* {} missing copyright.\n".format(orig_path))

        if report != "":
            self.add_failure("""
In most cases you do not need to do anything here, especially if the files
reported below are going into ext/ and if license was approved for inclusion
into ext/ already. Fix any missing license/copyright issues. The license
exception if a JFYI for the maintainers and can be overriden when merging the
pull request.\n\n""" + report)


class Identity(ComplianceTest):
    """
    Checks if Emails of author and signed-off messages are consistent.
    """
    name = "Identity/Emails"
    doc = "https://docs.zephyrproject.org/latest/contribute/#commit-guidelines"
    path = GIT_TOP
    quote_fails = False

    def run(self):
        # git rev-list and git log don't depend on the current
        # (sub)directory unless explicited.

        for shaidx in get_shas(commit_range):
            commit = git("log", "--decorate=short", "-n 1", shaidx)
            signed = []
            author = ""
            sha = ""
            parsed_addr = None
            for line in commit.split("\n"):
                match = re.search(r"^commit\s([^\s]*)", line)
                if match:
                    sha = match.group(1)
                match = re.search(r"^Author:\s(.*)", line)
                if match:
                    author = match.group(1)
                    parsed_addr = parseaddr(author)
                match = re.search(r"signed-off-by:\s(.*)", line, re.IGNORECASE)
                if match:
                    signed.append(match.group(1))

            error1 = "%s: author email (%s) needs to match one of the signed-off-by entries." % (
                sha, author)
            error2 = "%s: author email (%s) does not follow the syntax: First Last <email>." % (
                sha, author)
            failure = None
            if author not in signed:
                failure = error1

            if not parsed_addr or len(parsed_addr[0].split(" ")) < 2:
                if not failure:

                    failure = error2
                else:
                    failure = failure + "\n" + error2

            if failure:
                self.add_failure(failure)


def init_logs(cli_arg):
    # Initializes logging

    # TODO: there may be a shorter version thanks to:
    # logging.basicConfig(...)

    global logger

    level = os.environ.get('LOG_LEVEL', "WARN")

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(levelname)-8s: %(message)s'))

    logger = logging.getLogger('')
    logger.addHandler(console)
    logger.setLevel(cli_arg if cli_arg else level)

    logging.info("Log init completed, level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))


def set_pending():
    # Sets 'pending' status for all tests for the commit given by --sha

    for testcase in ComplianceTest.__subclasses__():
        print("Creating pending status for " + testcase.name)
        github_commit.create_status(
            'pending', testcase.doc,
            'Run in progress (build no. {})'.format(build_number),
            testcase.name)


def report_test_results_to_github(tests):
    # Reports test results to Github. 'test_results' is a list of Test
    # instances for tests that have been run.

    name2doc = {testcase.name: testcase.doc
                for testcase in ComplianceTest.__subclasses__()}

    def set_commit_status(status, msg):
        # 'case' gets set in the loop.
        # pylint: disable=undefined-loop-variable
        github_commit.create_status(
            status, name2doc[test.name],
            "{} (build no. {})".format(msg, build_number), test.name)

    msg = ""  # Message posted to GitHub
    failed = False

    for test in tests:
        github_comment(str(test))  # TODO: remove
        if test.error_msg:
            failed = True
            msg += "## {} (internal test error)\n\n```\n{}\n```\n\n" \
                   .format(test.name, test.error_msg)
            set_commit_status(
                'error', 'Error during verification, please report!')
        elif test.fail_msg:
            failed = True
            msg += "## {} (failures)\n\n".format(test.name)
            if test.quote_fails:
                msg += "```\n" + test.fail_msg + "\n```"
            else:
                msg += test.fail_msg
            msg += "\n\n"
            set_commit_status('failure', 'Checks failed')
        elif test.skip_msg:
            set_commit_status('success', 'Checks skipped')
        else:
            set_commit_status('success', 'Checks passed')

        # Always show any informative messages
        if test.info_msg:
            msg += "## {} (informative)\n\n```\n{}\n```\n\n" \
                   .format(test.name, test.info_msg)

    if failed:
        github_comment(
            "**Some checks failed. Please fix and resubmit.**\n\n" + msg)
    elif msg or get_bot_comment():
        if get_bot_comment():
            # Post a success message if a message was posted by the bot
            # previously (probably with a failure message), even if no test
            # case generated any output. We edit the old message.
            github_comment("**All checks are passing now.**" + msg)
        else:
            # Tests succeeded right away, but some tests generated informative
            # messages (e.g. CheckPatch). Show them.
            github_comment(
                "**All checks passed, but see messages below.**" + msg)


def github_comment(msg):
    # Posts 'msg' to GitHub, or edits the previous message posted by the bot if
    # it has already posted a message. Automatically adds a message with a tip
    # re. the bot editing the message.

    if not github_pr:
        # No pull request to post the message in
        return

    msg += EDIT_TIP

    bot_comment = get_bot_comment()
    if bot_comment:
        if bot_comment.body != msg:
            bot_comment.edit(msg)
    else:
        github_pr.create_issue_comment(msg)


def get_bot_comment():
    # Returns any previous comment posted by the bot in 'github_pr', or None if
    # the bot hasn't posted any comment (or there's no pull request)

    global cached_bot_comment

    def get_comment():
        if not github_pr:
            return None

        for comment in github_pr.get_issue_comments():
            if comment.user.login != os.getenv('GH_USERNAME', 'zephyrbot'):
                continue

            if EDIT_TIP in comment.body:
                return comment

        return None

    if cached_bot_comment == 0:
        cached_bot_comment = get_comment()
    return cached_bot_comment


# Cache used by get_bot_comment(). Use 0 instead of None for "no cached value"
# so that None (no comment) can be cached.
cached_bot_comment = 0


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check for coding style and documentation warnings.")
    parser.add_argument('-c', '--commits', default="HEAD~1..",
                        help='''Commit range in the form: a..[b], default is
                        HEAD~1..HEAD''')
    parser.add_argument('-g', '--github', action="store_true",
                        help="Post results as comments in the PR on GitHub")

    parser.add_argument('-r', '--repo', default=None,
                        help="GitHub repository")
    parser.add_argument('-p', '--pull-request', default=0, type=int,
                        help="Pull request number")

    parser.add_argument('-s', '--status', action="store_true",
                        help="Set status on GitHub to pending and exit")
    parser.add_argument('-S', '--sha', default=None, help="Commit SHA")
    parser.add_argument('-o', '--output', default="compliance.xml",
                        help='''Name of outfile in JUnit format,
                        default is ./compliance.xml''')

    parser.add_argument('-l', '--list', action="store_true",
                        help="List all checks and exit")

    parser.add_argument("-v", "--loglevel", help="python logging level")

    parser.add_argument('-m', '--module', action="append", default=[],
                        help="Checks to run. All checks by default.")

    parser.add_argument('-e', '--exclude-module', action="append", default=[],
                        help="Do not run the specified checks")

    parser.add_argument('-j', '--previous-run', default=None,
                        help='''Pre-load JUnit results in XML format
                        from a previous run and combine with new results.''')

    return parser.parse_args()


def init_github(args):
    # Initializes a GitHub connection

    global commit_sha
    global github_repo
    global github_pr
    global github_commit
    global build_number

    if args.repo is None:
        err("--repo <name> must be passed when connecting to GitHub")

    if args.sha is None:
        err("--sha <SHA> must be passed when connecting to GitHub")

    commit_sha = args.sha

    if 'GH_TOKEN' not in os.environ:
        err("the GH_TOKEN environment variable must be set when connecting "
            "to GitHub")

    github_repo = Github(os.environ['GH_TOKEN']).get_repo(args.repo)
    github_commit = github_repo.get_commit(commit_sha)
    if args.pull_request:
        github_pr = github_repo.get_pull(args.pull_request)
    else:
        github_pr = None

    # Get the shippable build number, useful to find logs
    build_number = os.environ.get("BUILD_NUMBER")
    if build_number is None:
        err("the BUILD_NUMBER environment variable must be set when "
            "connecting to GitHub")


def run_tests(args):
    # Runs all (enabled) tests, returning a list of ComplianceTest instances
    # for the finished tests. 'args' is the parsed command-line arguments.

    tests = []

    for testcase in ComplianceTest.__subclasses__():
        if args.module:
            if testcase.name not in args.module:
                continue
        elif testcase.name in args.exclude_module:
            print("Skipping " + testcase.name)
            continue

        test = testcase()
        try:
            print("Running {:16} tests in {} ..."
                  .format(test.name, test.path))
            test.run()
        except EndTest:
            pass
        tests.append(test)

    return tests


def write_xml(args, tests):
    # Writes compliance.xml. 'args' is the parsed command-line arguments, and
    # 'tests' a list of Test instances for tests that have been run. Returns
    # True on success and False on failure.

    if args.previous_run:
        if not os.path.exists(args.previous_run):
            # This probably means that an earlier pass had an internal error
            # (the script is currently run multiple times by the ci-pipelines
            # repo). Since that earlier pass might've posted an error to
            # GitHub, avoid generating a GitHub comment here, by avoiding
            # sys.exit() (which gets caught in main()).
            print("error: '{}' not found".format(args.previous_run),
                  file=sys.stderr)
            return False

        logging.info("Loading previous results from " + args.previous_run)
        for loaded_suite in JUnitXml.fromfile(args.previous_run):
            suite = loaded_suite
            break
    else:
        suite = TestSuite("Compliance")

    for test in tests:
        suite.add_testcase(test.to_junit_testcase())

    xml = JUnitXml()
    xml.add_testsuite(suite)
    xml.update_statistics()
    xml.write(args.output, pretty=True)

    return True


def _main(args):
    # The "real" main(), which is wrapped to catch exceptions and report them
    # to GitHub. Returns the number of test failures.

    # The commit range passed in --commit, e.g. 'HEAD~3..'
    global commit_range

    init_logs(args.loglevel)

    if args.list:
        for testcase in ComplianceTest.__subclasses__():
            print(testcase.name)
        return 0

    if args.status:
        set_pending()
        return 0

    commit_range = args.commits
    if not commit_range:
        err("No commit range given")

    tests = run_tests(args)

    if args.github:
        report_test_results_to_github(tests)

    if not write_xml(args, tests):
        return 1

    print("\nComplete results in " + args.output)

    # Return number of failures
    n_fails = 0
    for test in tests:
        if test.fail_msg or test.error_msg:
            n_fails += 1
    return n_fails


def main():
    args = parse_args()

    # Initialize the GitHub connection early so that any errors from the script
    # itself can be reported
    if args.github or args.status:
        init_github(args)

    try:
        n_fails = _main(args)
    except BaseException:
        # Catch BaseException instead of Exception to include stuff like
        # SystemExit (raised by sys.exit())

        if args.github:
            github_comment(
                "**Internal CI Error.**\n\nPython exception in `{}`:\n\n"
                "```\n{}\n```".format(__file__, traceback.format_exc()))

        raise

    sys.exit(n_fails)


def err(msg):
    sys.exit("error: " + msg)


if __name__ == "__main__":
    main()
