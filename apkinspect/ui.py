"""Terminal presentation helpers with an optional Rich backend."""
import os
import sys
import time
from typing import Optional, TextIO


class TaskProgress:
    def __init__(self, ui: 'UI', label: str, total: Optional[int] = None):
        self.ui = ui
        self.label = label
        self.total = total
        self.completed = 0
        self._rich_progress = None
        self._task_id = None
        self._last_render = 0.0
        if not ui.show_progress:
            return
        if ui.console is not None:
            try:
                from rich.progress import BarColumn, Progress, TaskProgressColumn
                from rich.progress import TextColumn, TimeElapsedColumn
                self._rich_progress = Progress(
                    TextColumn('[progress.description]{task.description}'),
                    BarColumn(),
                    TaskProgressColumn(),
                    TimeElapsedColumn(),
                    console=ui.console,
                    transient=True,
                )
                self._rich_progress.start()
                self._task_id = self._rich_progress.add_task(label, total=total)
                return
            except ImportError:
                self._rich_progress = None
        self._render(force=True)

    def _render(self, force: bool = False, final: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_render < 0.08:
            return
        self._last_render = now
        if self.total is None:
            frames = '|/-\\'
            frame = frames[int(now * 8) % len(frames)]
            text = '%s %s' % (frame, self.label)
        else:
            ratio = min(1.0, self.completed / max(1, self.total))
            width = 24
            filled = int(width * ratio)
            bar = '#' * filled + '-' * (width - filled)
            text = '%s [%s] %3d%% (%d/%d)' % (
                self.label, bar, int(ratio * 100), self.completed, self.total)
        text = text[:100]
        if self.ui.is_tty or self.ui.progress_mode == 'always':
            self.ui._write_raw('\r' + text)
        elif force or final:
            self.ui._write_raw(text + '\n')
        if final and (self.ui.is_tty or self.ui.progress_mode == 'always'):
            self.ui._write_raw('\n')

    def advance(self, amount: int = 1, detail: Optional[str] = None) -> None:
        self.completed += amount
        if self._rich_progress is not None:
            if detail:
                self._rich_progress.update(self._task_id, completed=self.completed,
                                           description=detail)
            else:
                self._rich_progress.update(self._task_id, completed=self.completed)
        else:
            self._render()

    def finish(self, detail: Optional[str] = None) -> None:
        if self._rich_progress is not None:
            if detail:
                self._rich_progress.update(self._task_id, completed=self.completed,
                                           description=detail)
            self._rich_progress.stop()
        elif self.ui.show_progress:
            self._render(force=True, final=True)

    def __enter__(self) -> 'TaskProgress':
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.finish()


class UI:
    _COLORS = {
        'cyan': '\033[36m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'red': '\033[31m',
        'dim': '\033[2m',
        'bold': '\033[1m',
    }
    _RESET = '\033[0m'

    def __init__(self, quiet: bool = False, color: bool = True,
                 progress: str = 'auto', stream: Optional[TextIO] = None):
        self.quiet = quiet
        self.progress_mode = progress
        self.stream = stream or sys.stderr
        try:
            self.is_tty = bool(self.stream.isatty())
        except (AttributeError, OSError):
            self.is_tty = False
        self.color = color and 'NO_COLOR' not in os.environ
        self.show_status = not quiet and (self.is_tty or progress == 'always')
        self.show_progress = not quiet and progress != 'never' and self.show_status
        self.console = None
        if self.is_tty and (self.show_status or self.show_progress):
            try:
                from rich.console import Console
                self.console = Console(file=self.stream, no_color=not self.color,
                                       highlight=False, soft_wrap=True)
            except ImportError:
                self.console = None

    def _write_raw(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()

    def _emit(self, prefix: str, message: str, style: str, force: bool = False) -> None:
        if self.quiet and not force:
            return
        if not self.show_status and not force:
            return
        if self.console is not None:
            self.console.print('[%s]%s[/] %s' % (style, prefix, message))
            return
        if self.color and style in self._COLORS:
            self._write_raw('%s%s%s %s\n' % (self._COLORS[style], prefix,
                                              self._RESET, message))
        else:
            self._write_raw('%s %s\n' % (prefix, message))

    def command_start(self, command: str) -> None:
        self._emit('>', command, 'cyan')

    def command_done(self, command: str, seconds: float) -> None:
        self._emit('OK', '%s completed in %.2fs' % (command, seconds), 'green')

    def info(self, message: str) -> None:
        self._emit('INFO', message, 'cyan')

    def success(self, message: str) -> None:
        self._emit('OK', message, 'green')

    def warn(self, message: str) -> None:
        self._emit('WARN', message, 'yellow')

    def error(self, message: str) -> None:
        self._emit('ERROR:', message, 'red', force=True)

    def interrupted(self) -> None:
        self._emit('STOP', 'interrupted', 'yellow', force=True)

    def rule(self, title: str) -> None:
        if self.quiet or not self.show_status:
            return
        if self.console is not None:
            self.console.rule(title)
        else:
            self._write_raw('\n-- %s %s\n' % (title, '-' * max(0, 60 - len(title))))

    def progress(self, label: str, total: Optional[int] = None) -> TaskProgress:
        return TaskProgress(self, label, total)


def ui_for(args) -> UI:
    value = getattr(args, 'ui', None)
    if value is not None:
        return value
    return UI(quiet=True, color=False, progress='never')
