import io
import unittest

from apkinspect.__main__ import build_parser
from apkinspect.ui import UI, ui_for


class UITests(unittest.TestCase):
    def test_quiet_ui_is_silent(self):
        stream = io.StringIO()
        ui = UI(quiet=True, color=False, progress='never', stream=stream)
        ui.command_start('demo')
        ui.command_done('demo', 0.1)
        ui.error('failure')
        self.assertIn('ERROR: failure', stream.getvalue())
        self.assertNotIn('demo', stream.getvalue())

    def test_plain_progress_fallback(self):
        stream = io.StringIO()
        ui = UI(quiet=False, color=False, progress='always', stream=stream)
        with ui.progress('chunks', 2) as progress:
            progress.advance()
            progress.advance()
        self.assertIn('chunks', stream.getvalue())
        self.assertIn('100%', stream.getvalue())

    def test_ui_options_work_before_and_after_command(self):
        parser = build_parser()
        before = parser.parse_args(['--quiet', '--progress', 'never', 'upd', 'x.apk', '-o', 'out'])
        after = parser.parse_args(['upd', 'x.apk', '-o', 'out', '--no-color', '--progress', 'never'])
        self.assertTrue(before.quiet)
        self.assertEqual(before.progress, 'never')
        self.assertTrue(after.no_color)
        self.assertEqual(after.progress, 'never')

    def test_ui_for_missing_attribute_is_quiet(self):
        class Args:
            pass
        self.assertTrue(ui_for(Args()).quiet)


if __name__ == '__main__':
    unittest.main()
