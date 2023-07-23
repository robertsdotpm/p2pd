import platform
import sys
import os
import multiprocessing
from p2pd.test_init import *
from p2pd.cmd_tools import *

async def test_esc(arg):
    # So paths with spaces don't break the command.
    py = os.path.basename(sys.executable)
    c = "import sys; print(sys.argv[1], end='')"
    buf = rf"""{py} -c "{c}" {arg}"""
    return await cmd(buf)

class TestCmd(unittest.IsolatedAsyncioTestCase):
    async def test_escape(self):
        if platform.system() in ["Windows"]:
            tests = [
                # Regular command with double quotes in it.
                [
                    'test "somèthing"',
                    '"test \\"somèthing\\""'
                ],

                # Sneaky attempt to escape enclosing last slash.
                [
                    'test x\\',
                    '"test x\\\\"'
                ],

                # Another attempt to escape last enclosing slash.
                # As long as it's in double quotes it has no effect.
                [
                    'test x^',
                    '"test x^^"'
                ],

                # Test some special charas.
                [
                    'test ! %',
                    '"test ^! ^%"'

                ],

                # Test escape list impact inside string.
                [
                    ',:;=\t&><|',
                    '"^,:^;=\t^&^>^<^|"'
                ],

                # Test unbalanced double quotes escape.
                [
                    'hax """',
                    '"hax \\"\\"\\""'
                ]
            ]

        if platform.system() == "Linux":
            tests = [
                # Regular command with double quotes in it.
                [
                    'tèst "something"',
                    "'tèst \"something\"'"
                ],

                # Sneaky attempt to escape enclosing last slash.
                [
                    'test x\\',
                    "'test x\\'"
                ],

                # Test some special charas.
                [
                    'test ! %',
                    "'test ! %'"

                ],

                # Test escape list impact inside string.
                [
                    ',:;=\t&><|',
                    "',:;=\t&><|'"
                ],

                # Test unbalanced double quotes escape.
                # IDK why it's escaped like this but seems it works.
                [
                    'hax \'\'\'',
                    '\'hax \'"\'"\'\'"\'"\'\'"\'"\'\''
                ]
            ]

        if platform.system() in ["FreeBSD", "Darwin"]:
            tests = [
                # Regular command with double quotes in it.
                [
                    'tèst "something"',
                    '"tèst \\"something\\""'
                ],

                # Sneaky attempt to escape enclosing last slash.
                [
                    'test x\\',
                    '"test x\\\\"'
                ],

                # Another attempt to escape last enclosing slash.
                # As long as it's in double quotes it has no effect.
                [
                    'test x^',
                    '"test x^"'
                ],

                # Test some special charas.
                [
                    'test ! %',
                    '"test ! %"'

                ],

                # Test escape list impact inside string.
                [
                    ',:;=\t&><|',
                    '",:;=\t&><|"'
                ],

                # Test unbalanced double quotes escape.
                [
                    'hax """',
                    '"hax \\"\\"\\""'
                ]
            ]

        esc = get_arg_escape_func()
        for test in tests:
            unsafe_param, safe_param = test
            out_param = esc(unsafe_param)
            self.assertEqual(out_param, safe_param)

            # How is param serialized.
            exp_param = await test_esc(safe_param)
            if exp_param != unsafe_param:
                print(f"{exp_param} != {unsafe_param}")

            self.assertTrue(isinstance(exp_param, str))

    async def test_cmd(self):
        py = os.path.basename(sys.executable)
        out = await cmd(f"""{py} -c "print('something')" """)
        self.assertTrue("something" in out)

    async def test_is_root(self):
        b = is_root()
        self.assertTrue(b in [True, False])

    async def test_nt_is_admin(self):
        if platform.system() != "Windows":
            return

        b = nt_is_admin()
        self.assertTrue(b in [True, False])

    async def test_nt_is_pshell_restricted(self):
        if platform.system() != "Windows":
            return

        out = await is_pshell_restricted()
        self.assertTrue(out in [True, False])

    async def test_nt_set_pshell_unrestricted(self):
        if platform.system() != "Windows":
            return

        # Process must be elevated to test this.
        if not is_root():
            return

        await nt_set_pshell_unrestricted()
        out = await is_pshell_restricted()
        self.assertTrue(out in (True, False))

if __name__ == '__main__':
    multiprocessing.set_start_method("spawn")
    main()