# Fastagram - anagram finder
# written by no1453@gmail.com
# Michael Hoskins 2026.01.03
# Revised 2026.09.30 — bounded search, cancellable workers, letter-count signatures, common-word list, 14-point UI

import multiprocessing
import os
import queue
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, scrolledtext, ttk

# One slot per letter a-z. Word signatures are stored packed in WORD_SIGS.
ALPH = 26
DEFAULT_MIN_LEN = 3
DEFAULT_MAX_WORDS = 10
DEFAULT_MAX_RESULTS = 5000
# Below this many opening branches, one thread is faster than starting processes.
MP_BRANCH_THRESHOLD = 24
PHRASE_BATCH = 40
# Point size. Windows still stretches this DPI-unaware window by the desktop zoom,
# so 14pt here is about 14pt on screen at 125%.
UI_FONT_FAMILY = "Segoe UI"
UI_FONT_SIZE = 14

WORD_LIST: list[str] = []
WORD_SIGS = bytearray()
DICT_PATH = ""

_task_q = None
_result_q = None
_cancel = None
_workers: list[multiprocessing.Process] = []
_worker_lock = threading.Lock()


def app_base() -> str:
    """Folder of the script, or of the frozen executable."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def dictionary_path() -> str:
    """Common-word list: words.txt beside the program, else a copy bundled in the executable."""
    beside = os.path.join(app_base(), "words.txt")
    if os.path.isfile(beside):
        return beside
    bundled_root = getattr(sys, "_MEIPASS", None)
    if bundled_root:
        bundled = os.path.join(bundled_root, "words.txt")
        if os.path.isfile(bundled):
            return bundled
    return beside


def full_dictionary_path() -> str | None:
    """Unfiltered list, kept as words-all.txt beside the program."""
    path = os.path.join(app_base(), "words-all.txt")
    if os.path.isfile(path):
        return path
    return None


def load_words(words: list[str]) -> None:
    """Install a word list and its packed letter counts. Duplicates are dropped."""
    global WORD_LIST, WORD_SIGS
    unique: list[str] = []
    seen: set[str] = set()
    for raw in words:
        word = raw.strip().lower()
        if not word or word in seen:
            continue
        if any(ord(ch) < 97 or ord(ch) > 122 for ch in word):
            continue
        seen.add(word)
        unique.append(word)
    sigs = bytearray(len(unique) * ALPH)
    for index, word in enumerate(unique):
        base = index * ALPH
        for ch in word:
            sigs[base + ord(ch) - 97] += 1
    WORD_LIST = unique
    WORD_SIGS = sigs


def load_dictionary(path: str) -> None:
    """Load a word list. The main process drops workers so they cannot keep an old list."""
    global DICT_PATH
    with open(path, encoding="utf-8-sig") as handle:
        lines = handle.readlines()
    if multiprocessing.current_process().name == "MainProcess":
        _shutdown_workers()
    DICT_PATH = os.path.abspath(path)
    load_words(lines)
    if not WORD_LIST:
        raise ValueError(f"No words found in {path}")


def ascii_letters(text: str) -> str:
    """Keep a-z only, so names and phrases can be pasted with spaces or punctuation."""
    return "".join(ch.lower() for ch in text if "a" <= ch.lower() <= "z")


def ascii_words(text: str) -> list[str]:
    words = []
    for token in text.split():
        word = ascii_letters(token)
        if word:
            words.append(word)
    return words


def counts_of(letters: str) -> list[int]:
    counts = [0] * ALPH
    for ch in letters:
        counts[ord(ch) - 97] += 1
    return counts


def counts_fit(need: list[int], avail: list[int]) -> bool:
    for index in range(ALPH):
        if need[index] > avail[index]:
            return False
    return True


def sig_fits(base: int, avail: list[int]) -> bool:
    # Unrolled so the search and the dictionary scan stay in a tight loop.
    sigs = WORD_SIGS
    return (
        sigs[base] <= avail[0]
        and sigs[base + 1] <= avail[1]
        and sigs[base + 2] <= avail[2]
        and sigs[base + 3] <= avail[3]
        and sigs[base + 4] <= avail[4]
        and sigs[base + 5] <= avail[5]
        and sigs[base + 6] <= avail[6]
        and sigs[base + 7] <= avail[7]
        and sigs[base + 8] <= avail[8]
        and sigs[base + 9] <= avail[9]
        and sigs[base + 10] <= avail[10]
        and sigs[base + 11] <= avail[11]
        and sigs[base + 12] <= avail[12]
        and sigs[base + 13] <= avail[13]
        and sigs[base + 14] <= avail[14]
        and sigs[base + 15] <= avail[15]
        and sigs[base + 16] <= avail[16]
        and sigs[base + 17] <= avail[17]
        and sigs[base + 18] <= avail[18]
        and sigs[base + 19] <= avail[19]
        and sigs[base + 20] <= avail[20]
        and sigs[base + 21] <= avail[21]
        and sigs[base + 22] <= avail[22]
        and sigs[base + 23] <= avail[23]
        and sigs[base + 24] <= avail[24]
        and sigs[base + 25] <= avail[25]
    )


def candidate_indices(letters: str, min_len: int) -> list[int]:
    """Dictionary entries that can be spelled from these letters and are long enough."""
    avail = counts_of(letters)
    words = WORD_LIST
    chosen = []
    append = chosen.append
    for index, word in enumerate(words):
        if len(word) < min_len:
            continue
        base = index * ALPH
        if sig_fits(base, avail):
            append(index)
    return chosen


def build_index(cand_indices: list[int]):
    """Local word table and, for each letter, the local indices of words that use it.

    Local index i always means cand_indices[i]. The per-letter lists are longest-first
    so interesting phrases show up early. That order is deterministic.
    """
    words = [WORD_LIST[gi] for gi in cand_indices]
    bases = [gi * ALPH for gi in cand_indices]
    inv: list[list[int]] = [[] for _ in range(ALPH)]
    sigs = WORD_SIGS
    for local, base in enumerate(bases):
        for slot in range(ALPH):
            if sigs[base + slot]:
                inv[slot].append(local)
    for slot in range(ALPH):
        inv[slot].sort(key=lambda local, words=words: (-len(words[local]), words[local]))
    return words, bases, inv


def rarest_letter(avail: list[int], inv: list[list[int]]) -> int:
    """Letter still unused that the fewest candidate words can cover."""
    best = -1
    best_n = 10**9
    for slot in range(ALPH):
        if avail[slot]:
            count = len(inv[slot])
            if count < best_n:
                best_n = count
                best = slot
    return best


def opening_branches(bases: list[int], inv: list[list[int]], avail: list[int]) -> list[int]:
    pivot = rarest_letter(avail, inv)
    if pivot < 0:
        return []
    return [local for local in inv[pivot] if sig_fits(bases[local], avail)]


def _interest_key(phrase: str) -> tuple:
    parts = phrase.split()
    longest = max(len(part) for part in parts)
    return (len(parts), -longest, phrase)


def collect_anagrams(
    cand_indices: list[int],
    avail: list[int],
    required: list[str],
    branch_ids: list[int],
    min_len: int,
    max_words: int,
    halt,
    on_phrase,
    on_branch,
) -> None:
    """Find phrases that use every remaining letter.

    Each step places a word containing the scarcest remaining letter. Every solution
    has to cover that letter, so the search stays complete. Phrases are emitted in
    canonical word order. `branch_ids` are the opening words for this worker.
    `halt.is_set()` ends the walk; Stop and the result cap both set it.
    """
    if not cand_indices or not branch_ids:
        return
    words, bases, inv = build_index(cand_indices)
    avail = avail[:]
    sigs = WORD_SIGS
    seen: set[str] = set()
    checks = 0

    def take(base: int) -> None:
        for slot in range(ALPH):
            avail[slot] -= sigs[base + slot]

    def give(base: int) -> None:
        for slot in range(ALPH):
            avail[slot] += sigs[base + slot]

    def emit(extra: list[str]) -> None:
        phrase = " ".join(sorted(required + extra))
        if phrase not in seen:
            seen.add(phrase)
            on_phrase(phrase)

    def bt(left: int, extra: list[str]) -> None:
        nonlocal checks
        checks += 1
        if checks % 32 == 0 and halt.is_set():
            return
        if left == 0:
            emit(extra)
            return
        if len(required) + len(extra) >= max_words or left < min_len:
            return
        pivot = rarest_letter(avail, inv)
        if pivot < 0 or not inv[pivot]:
            return
        for tried, local in enumerate(inv[pivot]):
            if tried % 32 == 0 and halt.is_set():
                return
            base = bases[local]
            if not sig_fits(base, avail):
                continue
            word = words[local]
            take(base)
            extra.append(word)
            bt(left - len(word), extra)
            extra.pop()
            give(base)
            if halt.is_set():
                return

    left0 = sum(avail)
    extra: list[str] = []
    for local in branch_ids:
        if halt.is_set():
            break
        base = bases[local]
        word = words[local]
        if len(word) > left0 or not sig_fits(base, avail):
            on_branch()
            continue
        take(base)
        extra.append(word)
        bt(left0 - len(word), extra)
        extra.pop()
        give(base)
        on_branch()


def _outcome(user_stop, hit_extra: bool) -> str:
    if user_stop.is_set():
        return "stopped"
    if hit_extra:
        return "limit"
    return "complete"


def run_serial_search(
    cand_indices: list[int],
    avail: list[int],
    required: list[str],
    branch_ids: list[int],
    min_len: int,
    max_words: int,
    max_results: int,
    halt,
    user_stop,
    on_batch,
    on_progress,
) -> str:
    found = 0
    batch: list[str] = []
    hit_extra = False
    done = 0
    total = len(branch_ids)

    def flush() -> None:
        nonlocal batch
        if batch:
            on_batch(batch)
            batch = []

    def on_phrase(phrase: str) -> None:
        nonlocal found, hit_extra
        if found >= max_results:
            hit_extra = True
            halt.set()
            return
        found += 1
        batch.append(phrase)
        if len(batch) >= PHRASE_BATCH:
            flush()

    def on_branch() -> None:
        nonlocal done
        done += 1
        if done == total or done % 5 == 0:
            on_progress(done, total)

    collect_anagrams(
        cand_indices, avail, required, branch_ids, min_len, max_words, halt, on_phrase, on_branch
    )
    flush()
    if total:
        on_progress(done, total)
    return _outcome(user_stop, hit_extra)


class _CancelFlag:
    """halt.is_set() view of the shared cancel counter workers inherit at startup."""

    def __init__(self, cell):
        self._cell = cell

    def is_set(self) -> bool:
        return self._cell.value != 0


def _signal_cancel() -> None:
    cell = _cancel
    if cell is None:
        return
    try:
        cell.value = 1
    except Exception:
        pass


def _worker_loop(task_q, result_q, cancel, dict_path: str) -> None:
    """Long-lived search process. The queues are inherited at spawn, not pickled later."""
    try:
        load_dictionary(dict_path)
        result_q.put(("ready", 1))
    except Exception as exc:
        try:
            result_q.put(("error", str(exc)))
        except Exception:
            pass
        return
    halt = _CancelFlag(cancel)
    while True:
        job = task_q.get()
        if job is None:
            return
        batch: list[str] = []
        branch_marks = 0

        def flush_phrases() -> None:
            nonlocal batch
            if not batch:
                return
            item = ("results", batch)
            batch = []
            try:
                result_q.put(item, timeout=0.5)
            except Exception:
                return

        def flush_branches() -> None:
            nonlocal branch_marks
            if not branch_marks:
                return
            try:
                result_q.put(("branch", branch_marks), timeout=0.2)
            except Exception:
                pass
            branch_marks = 0

        def on_phrase(phrase: str) -> None:
            if halt.is_set():
                return
            batch.append(phrase)
            if len(batch) >= PHRASE_BATCH:
                flush_phrases()

        def on_branch() -> None:
            nonlocal branch_marks
            branch_marks += 1
            if branch_marks >= 8:
                flush_branches()

        try:
            collect_anagrams(
                job["cand_indices"],
                job["avail"],
                job["required"],
                job["branch_ids"],
                job["min_len"],
                job["max_words"],
                halt,
                on_phrase,
                on_branch,
            )
            flush_phrases()
            flush_branches()
        except Exception as exc:
            try:
                result_q.put(("error", str(exc)))
            except Exception:
                pass
        finally:
            for _attempt in range(10):
                try:
                    result_q.put(("job_done", 1), timeout=0.3)
                    break
                except Exception:
                    if halt.is_set():
                        break


def _ensure_workers() -> None:
    """Start one process per core. Later searches reuse them."""
    global _task_q, _result_q, _cancel, _workers
    with _worker_lock:
        if _workers and all(proc.is_alive() for proc in _workers):
            return
        workers, result_q = _start_workers_locked()
    _wait_until_ready(workers, result_q)


def _start_workers_locked():
    global _task_q, _result_q, _cancel, _workers
    _stop_workers_locked()
    ctx = multiprocessing.get_context("spawn")
    _task_q = ctx.Queue()
    _result_q = ctx.Queue(maxsize=200)
    _cancel = ctx.Value("i", 0)
    count = os.cpu_count() or 2
    for _index in range(count):
        proc = ctx.Process(
            target=_worker_loop,
            args=(_task_q, _result_q, _cancel, DICT_PATH),
            daemon=True,
        )
        proc.start()
        _workers.append(proc)
    return list(_workers), _result_q


def _wait_until_ready(workers, result_q) -> None:
    ready = 0
    needed = len(workers)
    deadline = time.monotonic() + 60
    while ready < needed:
        if time.monotonic() > deadline:
            _shutdown_workers()
            raise RuntimeError("Search workers did not start.")
        try:
            message = result_q.get(timeout=0.2)
        except queue.Empty:
            if any(not proc.is_alive() for proc in workers):
                _shutdown_workers()
                raise RuntimeError("A search worker exited while loading the dictionary.")
            continue
        except (OSError, EOFError, ValueError) as exc:
            _shutdown_workers()
            raise RuntimeError(f"Search workers failed to start: {exc}") from exc
        if message[0] == "ready":
            ready += 1
        elif message[0] == "error":
            _shutdown_workers()
            raise RuntimeError(message[1])


def _shutdown_workers() -> None:
    with _worker_lock:
        _stop_workers_locked()


def _stop_workers_locked() -> None:
    global _task_q, _result_q, _cancel, _workers
    workers = _workers
    task_q = _task_q
    result_q = _result_q
    _workers = []
    _task_q = None
    _result_q = None
    _cancel = None
    for proc in workers:
        if proc.is_alive():
            proc.terminate()
    for proc in workers:
        proc.join(timeout=2)
    for pipe in (task_q, result_q):
        if pipe is None:
            continue
        try:
            pipe.cancel_join_thread()
        except Exception:
            pass
        try:
            pipe.close()
        except Exception:
            pass


def _spread(items: list[int], chunks: int) -> list[list[int]]:
    buckets: list[list[int]] = [[] for _ in range(chunks)]
    for index, item in enumerate(items):
        buckets[index % chunks].append(item)
    return [bucket for bucket in buckets if bucket]


def run_parallel_search(
    cand_indices: list[int],
    avail: list[int],
    required: list[str],
    branch_ids: list[int],
    min_len: int,
    max_words: int,
    max_results: int,
    halt,
    user_stop,
    on_batch,
    on_progress,
    on_status,
) -> str:
    """Split opening words across long-lived processes. They stay up between searches."""
    workers = os.cpu_count() or 2
    chunks = _spread(branch_ids, min(len(branch_ids), workers * 4))
    if not _workers:
        on_status("Starting workers...")
    _ensure_workers()
    if user_stop.is_set():
        return "stopped"
    if _cancel is not None:
        _cancel.value = 0
    if user_stop.is_set():
        _signal_cancel()
        return "stopped"
    result_q = _result_q
    task_q = _task_q
    if result_q is None or task_q is None:
        raise RuntimeError("Search workers are not running.")
    for chunk in chunks:
        task_q.put({
            "cand_indices": cand_indices,
            "avail": avail,
            "required": required,
            "branch_ids": chunk,
            "min_len": min_len,
            "max_words": max_words,
        })

    seen: set[str] = set()
    batch: list[str] = []
    hit_extra = False
    done = 0
    total = len(branch_ids)
    jobs_left = len(chunks)
    error = None
    idle_after_halt: float | None = None

    def flush() -> None:
        nonlocal batch
        if batch:
            on_batch(batch)
            batch = []

    def accept(phrase: str) -> None:
        nonlocal hit_extra
        if phrase in seen or hit_extra:
            return
        if len(seen) >= max_results:
            hit_extra = True
            halt.set()
            _signal_cancel()
            return
        seen.add(phrase)
        batch.append(phrase)
        if len(batch) >= PHRASE_BATCH:
            flush()

    while jobs_left > 0:
        if user_stop.is_set():
            _signal_cancel()
            deadline = time.monotonic() + 1.0
            while jobs_left > 0 and time.monotonic() < deadline:
                try:
                    message = result_q.get(timeout=0.1)
                except queue.Empty:
                    continue
                jobs_left, done, error = _take_mp(
                    message, accept, on_progress, jobs_left, done, total, error, halt
                )
            flush()
            if jobs_left > 0:
                _shutdown_workers()
            return "stopped"
        try:
            message = result_q.get(timeout=0.2)
        except queue.Empty:
            if _workers and any(not proc.is_alive() for proc in _workers):
                error = error or "A search worker exited."
                _shutdown_workers()
                break
            if halt.is_set():
                now = time.monotonic()
                if idle_after_halt is None:
                    idle_after_halt = now
                elif now - idle_after_halt > 5:
                    _shutdown_workers()
                    break
            continue
        if halt.is_set():
            idle_after_halt = time.monotonic()
        jobs_left, done, error = _take_mp(
            message, accept, on_progress, jobs_left, done, total, error, halt
        )
    flush()
    if total:
        on_progress(min(done, total), total)
    if error and not user_stop.is_set() and not hit_extra:
        raise RuntimeError(error)
    return _outcome(user_stop, hit_extra)


def _take_mp(message, accept, on_progress, jobs_left, done, total, error, halt):
    kind = message[0]
    if kind == "results":
        for phrase in message[1]:
            accept(phrase)
    elif kind == "branch":
        done += message[1]
        if done > total:
            done = total
        if on_progress is not None:
            on_progress(done, total)
    elif kind == "error":
        error = message[1]
        halt.set()
        _signal_cancel()
    elif kind == "job_done":
        jobs_left -= 1
    return jobs_left, done, error


class FastagramApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Fastagram - Fast Anagram Finder")
        self.root.geometry("1180x1000")
        self.root.minsize(1000, 780)
        self.root.configure(padx=10, pady=10, bg="#1e1e1e")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._closed = False
        self._busy = False
        self._gen = 0
        self._halt = None
        self._user_stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._gui_q: queue.Queue = queue.Queue()
        self.found_phrases: list[str] = []
        self._progress_done = 0
        self._progress_total = 0

        self._build()
        self.letters_entry.focus_set()
        self.status_label.config(text=self._ready_status())

    def _ui_font(self) -> tkfont.Font:
        """14-point interface font, shared by the themed widgets and the text areas."""
        families = set(tkfont.families(self.root))
        family = UI_FONT_FAMILY if UI_FONT_FAMILY in families else tkfont.nametofont("TkDefaultFont").actual("family")
        font = tkfont.Font(self.root, family=family, size=UI_FONT_SIZE)
        for name in (
            "TkDefaultFont",
            "TkTextFont",
            "TkFixedFont",
            "TkMenuFont",
            "TkHeadingFont",
            "TkCaptionFont",
            "TkSmallCaptionFont",
            "TkIconFont",
            "TkTooltipFont",
        ):
            tkfont.nametofont(name).configure(family=family, size=UI_FONT_SIZE)
        return font

    def _build(self) -> None:
        bg = "#1e1e1e"
        fg = "#dddddd"
        entry_bg = "#333333"
        text_bg = "#252525"
        select_bg = "#007acc"
        self.ui_font = self._ui_font()
        ui_font = self.ui_font

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=ui_font)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg, font=ui_font)
        style.configure("Hint.TLabel", background=bg, foreground="#999999", font=ui_font)
        style.configure("TButton", background=bg, foreground=fg, font=ui_font)
        style.map("TButton", background=[("active", select_bg)], foreground=[("active", "white")])
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg, font=ui_font)
        style.map(
            "TEntry",
            fieldbackground=[("disabled", "#2a2a2a")],
            foreground=[("disabled", "#888888")],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=entry_bg,
            foreground=fg,
            background=bg,
            arrowcolor=fg,
            bordercolor="#444444",
            font=ui_font,
        )
        style.map(
            "TSpinbox",
            fieldbackground=[("disabled", "#2a2a2a")],
            foreground=[("disabled", "#888888")],
        )
        style.configure("TProgressbar", background=select_bg, troughcolor=bg)
        style.configure(
            "TCheckbutton",
            background=bg,
            foreground=fg,
            indicatorcolor=entry_bg,
            font=ui_font,
        )
        style.map(
            "TCheckbutton",
            background=[("active", bg), ("disabled", bg)],
            foreground=[("disabled", "#888888")],
            indicatorcolor=[("selected", select_bg), ("pressed", select_bg)],
        )

        top = ttk.Frame(self.root)
        top.pack(fill=tk.X)
        ttk.Label(top, text="Letters or phrase to anagram:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.letters_entry = ttk.Entry(top)
        self.letters_entry.grid(row=1, column=0, sticky=tk.EW, pady=2)
        ttk.Label(top, text="Required words:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.required_entry = ttk.Entry(top)
        self.required_entry.grid(row=3, column=0, sticky=tk.EW, pady=2)
        top.columnconfigure(0, weight=1)
        self.letters_entry.bind("<Return>", lambda _event: self.start_search())
        self.required_entry.bind("<Return>", lambda _event: self.start_search())

        limits = ttk.Frame(self.root)
        limits.pack(fill=tk.X, pady=(8, 0))
        self.min_len_var = tk.IntVar(value=DEFAULT_MIN_LEN)
        self.max_words_var = tk.IntVar(value=DEFAULT_MAX_WORDS)
        self.max_results_var = tk.IntVar(value=DEFAULT_MAX_RESULTS)
        self._limit_spins = []
        fields = (
            ("Min length", self.min_len_var, 1, 15),
            ("Max words", self.max_words_var, 1, 30),
            ("Max results", self.max_results_var, 1, 100_000),
        )
        for col, (label, var, lo, hi) in enumerate(fields):
            ttk.Label(limits, text=label).grid(row=0, column=col * 2, sticky=tk.W, padx=(0, 4))
            spin = ttk.Spinbox(limits, from_=lo, to=hi, textvariable=var, width=8)
            spin.grid(row=0, column=col * 2 + 1, sticky=tk.W, padx=(0, 18))
            self._limit_spins.append(spin)
        ttk.Label(
            limits,
            text="Min length skips short dictionary words. Required words are always kept.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, columnspan=6, sticky=tk.W, pady=(4, 0))

        dict_row = ttk.Frame(self.root)
        dict_row.pack(fill=tk.X, pady=(6, 0))
        self.common_only_var = tk.BooleanVar(value=True)
        self.common_check = ttk.Checkbutton(
            dict_row,
            text="Common words only",
            variable=self.common_only_var,
            command=self._on_common_toggle,
        )
        self.common_check.pack(side=tk.LEFT)
        ttk.Label(
            dict_row,
            text="Uncheck to search the full list, including rare and technical words.",
            style="Hint.TLabel",
        ).pack(side=tk.LEFT, padx=(10, 0))

        buttons = ttk.Frame(self.root)
        buttons.pack(fill=tk.X, pady=10)
        self.possible_btn = ttk.Button(buttons, text="Find Possible Words", command=self.show_possible_words)
        self.possible_btn.pack(side=tk.LEFT, padx=(0, 5))
        self.clear_inputs_btn = ttk.Button(buttons, text="Clear Inputs", command=self.clear_inputs)
        self.clear_inputs_btn.pack(side=tk.LEFT, padx=5)
        self.clear_required_btn = ttk.Button(buttons, text="Clear Required", command=self.clear_required)
        self.clear_required_btn.pack(side=tk.LEFT, padx=5)
        self.find_btn = ttk.Button(buttons, text="Find Anagrams", command=self.start_search)
        self.find_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(buttons, text="Stop Search", command=self.stop_search, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.root.bind("<Escape>", lambda _event: self.stop_search())

        progress_row = ttk.Frame(self.root)
        progress_row.pack(fill=tk.X, pady=(0, 8))
        self.progress = ttk.Progressbar(progress_row, mode="determinate", length=400)
        self.progress.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.status_label = ttk.Label(progress_row, text="Ready")
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0))

        self.words_caption = ttk.Label(self.root, text="Possible words (double-click to add to required):")
        self.words_caption.pack(anchor=tk.W)

        word_buttons = ttk.Frame(self.root)
        word_buttons.pack(fill=tk.X, pady=2)
        self.clear_words_btn = ttk.Button(word_buttons, text="Clear Possible Words", command=self.clear_possible_words)
        self.clear_words_btn.pack(side=tk.LEFT)
        self.add_word_btn = ttk.Button(word_buttons, text="Add to Required", command=self.add_selected_word)
        self.add_word_btn.pack(side=tk.LEFT, padx=5)
        self.save_btn = ttk.Button(word_buttons, text="Save Anagrams", command=self.save_anagrams, state=tk.DISABLED)
        self.save_btn.pack(side=tk.RIGHT)

        words_frame = ttk.Frame(self.root)
        words_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))
        self.words_listbox = tk.Listbox(
            words_frame,
            height=7,
            exportselection=False,
            font=ui_font,
            bg=text_bg,
            fg=fg,
            selectbackground=select_bg,
        )
        words_scroll = ttk.Scrollbar(words_frame, orient=tk.VERTICAL, command=self.words_listbox.yview)
        self.words_listbox.configure(yscrollcommand=words_scroll.set)
        self.words_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        words_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.words_listbox.bind("<Double-Button-1>", self._on_double_click)

        ttk.Label(self.root, text="Anagrams:").pack(anchor=tk.W)
        self.clear_results_btn = ttk.Button(self.root, text="Clear Anagrams", command=self.clear_anagrams)
        self.clear_results_btn.pack(side=tk.BOTTOM, anchor=tk.W, pady=(2, 0))
        self.results = scrolledtext.ScrolledText(
            self.root, height=12, state=tk.DISABLED, wrap=tk.WORD, font=ui_font, bg=text_bg, fg=fg
        )
        self.results.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

    def _limits(self) -> tuple[int, int, int] | None:
        try:
            min_len = int(self.min_len_var.get())
            max_words = int(self.max_words_var.get())
            max_results = int(self.max_results_var.get())
        except (tk.TclError, ValueError):
            messagebox.showerror("Fastagram", "Search limits must be whole numbers.", parent=self.root)
            return None
        if not (1 <= min_len <= 15 and 1 <= max_words <= 30 and 1 <= max_results <= 100_000):
            messagebox.showerror(
                "Fastagram",
                "Min length is 1–15, max words is 1–30, and max results is 1–100000.",
                parent=self.root,
            )
            return None
        return min_len, max_words, max_results

    def _set_words(self, words: list[str]) -> None:
        self.words_listbox.delete(0, tk.END)
        for word in words:
            self.words_listbox.insert(tk.END, word)
        self.words_caption.config(
            text=f"Possible words ({len(words):,}) — double-click to add to required:"
        )

    def show_possible_words(self) -> None:
        if self._busy:
            return
        limits = self._limits()
        if limits is None:
            return
        min_len = limits[0]
        letters = ascii_letters(self.letters_entry.get())
        if not letters:
            messagebox.showwarning("Fastagram", "Enter some letters to anagram.", parent=self.root)
            return
        self.status_label.config(text="Finding words...")
        self.root.update_idletasks()
        indices = candidate_indices(letters, min_len)
        words = sorted(WORD_LIST[index] for index in indices)
        self._set_words(words)
        self.status_label.config(text=f"{len(words):,} words can be spelled from {len(letters)} letters")

    def clear_inputs(self) -> None:
        if self._busy:
            return
        self.letters_entry.delete(0, tk.END)
        self.required_entry.delete(0, tk.END)
        self.clear_possible_words()
        self.letters_entry.focus_set()

    def clear_required(self) -> None:
        if self._busy:
            return
        self.required_entry.delete(0, tk.END)

    def clear_possible_words(self) -> None:
        self.words_listbox.delete(0, tk.END)
        self.words_caption.config(text="Possible words (double-click to add to required):")

    def _append_required(self, word: str) -> None:
        if self._busy or not word:
            return
        current = self.required_entry.get().strip()
        if current:
            self.required_entry.insert(tk.END, " " + word)
        else:
            self.required_entry.insert(0, word)

    def add_selected_word(self) -> None:
        selection = self.words_listbox.curselection()
        if not selection:
            return
        self._append_required(self.words_listbox.get(selection[0]))

    def _on_double_click(self, event) -> None:
        size = self.words_listbox.size()
        if size <= 0:
            return
        index = self.words_listbox.nearest(event.y)
        if not 0 <= index < size:
            return
        box = self.words_listbox.bbox(index)
        if not box:
            return
        _x, y, _w, height = box
        if y <= event.y <= y + height:
            self._append_required(self.words_listbox.get(index))

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        entry_state = tk.DISABLED if busy else tk.NORMAL
        self.letters_entry.config(state=entry_state)
        self.required_entry.config(state=entry_state)
        for spin in self._limit_spins:
            spin.config(state=entry_state)
        self.possible_btn.config(state=entry_state)
        self.clear_inputs_btn.config(state=entry_state)
        self.clear_required_btn.config(state=entry_state)
        self.find_btn.config(state=entry_state)
        self.stop_btn.config(state=tk.NORMAL if busy else tk.DISABLED)
        self.clear_results_btn.config(state=entry_state)
        self.add_word_btn.config(state=entry_state)
        self.clear_words_btn.config(state=entry_state)
        self.common_check.config(state=entry_state)

    def _ready_status(self) -> str:
        kind = "common" if self.common_only_var.get() else "full"
        return f"Ready — {len(WORD_LIST):,} {kind} words"

    def _on_common_toggle(self) -> None:
        """Switch between words.txt and the saved full list in words-all.txt."""
        if self._closed or self._busy:
            return
        common = bool(self.common_only_var.get())
        if common:
            path = dictionary_path()
        else:
            path = full_dictionary_path()
            if not path:
                self.common_only_var.set(True)
                messagebox.showinfo(
                    "Fastagram",
                    "The full word list (words-all.txt) is not in the program folder.\n"
                    "Common words stay selected.",
                    parent=self.root,
                )
                return
        if not os.path.isfile(path):
            self.common_only_var.set(not common)
            messagebox.showerror(
                "Fastagram",
                f"Dictionary file not found:\n{path}",
                parent=self.root,
            )
            return
        if os.path.abspath(path) == DICT_PATH and WORD_LIST:
            self.status_label.config(text=self._ready_status())
            return
        self.status_label.config(text="Loading word list...")
        self.root.update_idletasks()
        try:
            load_dictionary(path)
        except (OSError, ValueError) as exc:
            self.common_only_var.set(not common)
            messagebox.showerror("Fastagram", f"Could not read the dictionary:\n{exc}", parent=self.root)
            self.status_label.config(text=self._ready_status())
            return
        self.clear_possible_words()
        self.found_phrases = []
        self._write_results([])
        self.save_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.status_label.config(text=self._ready_status())

    def start_search(self) -> None:
        if self._busy:
            return
        limits = self._limits()
        if limits is None:
            return
        min_len, max_words, max_results = limits
        letters = ascii_letters(self.letters_entry.get())
        required = ascii_words(self.required_entry.get())
        if not letters:
            messagebox.showwarning("Fastagram", "Enter some letters to anagram.", parent=self.root)
            return
        avail = counts_of(letters)
        needed = counts_of("".join(required))
        if not counts_fit(needed, avail):
            messagebox.showerror(
                "Fastagram",
                "Those required words use letters that are not in the source.",
                parent=self.root,
            )
            return
        for slot in range(ALPH):
            avail[slot] -= needed[slot]
        if any(avail) and len(required) >= max_words:
            messagebox.showerror(
                "Fastagram",
                "The required words already reach Max words, with letters left over. Raise Max words.",
                parent=self.root,
            )
            return

        self.status_label.config(text="Finding words...")
        self.root.update_idletasks()
        indices = candidate_indices(letters, min_len)
        self._set_words(sorted(WORD_LIST[index] for index in indices))

        self._gen += 1
        gen = self._gen
        self._user_stop.clear()
        self._halt = multiprocessing.Event()
        self.found_phrases = []
        self._progress_done = 0
        self._progress_total = 0
        self.progress["value"] = 0
        self._write_results([])
        self.save_btn.config(state=tk.DISABLED)
        self._set_busy(True)
        shown = ", ".join(required) if required else "none"
        self.status_label.config(text=f"Searching '{letters}' (required: {shown})")

        self._thread = threading.Thread(
            target=self._search_thread,
            args=(gen, indices, avail, required, min_len, max_words, max_results),
            daemon=True,
        )
        self._thread.start()
        self.root.after(40, lambda g=gen: self._check_queue(g))

    def _search_thread(
        self,
        gen: int,
        indices: list[int],
        avail: list[int],
        required: list[str],
        min_len: int,
        max_words: int,
        max_results: int,
    ) -> None:
        outcome = "complete"
        error = None
        try:
            if not any(avail):
                if required:
                    self._gui_q.put(("results", gen, [" ".join(sorted(required))]))
                return
            usable = [index for index in indices if sig_fits(index * ALPH, avail)]
            _words, bases, inv = build_index(usable)
            branches = opening_branches(bases, inv, avail)
            self._gui_q.put(("progress", gen, 0, len(branches)))
            if not branches:
                return

            delivered = False

            def on_batch(phrases: list[str]) -> None:
                nonlocal delivered
                delivered = True
                self._gui_q.put(("results", gen, phrases))

            def on_progress(done: int, total: int) -> None:
                self._gui_q.put(("progress", gen, done, total))

            def on_status(text: str) -> None:
                self._gui_q.put(("status", gen, text))

            parallel = len(branches) >= MP_BRANCH_THRESHOLD and (os.cpu_count() or 1) > 1
            if parallel:
                try:
                    outcome = run_parallel_search(
                        usable, avail, required, branches, min_len, max_words, max_results,
                        self._halt, self._user_stop, on_batch, on_progress, on_status,
                    )
                except Exception as exc:
                    if self._user_stop.is_set():
                        outcome = "stopped"
                    elif delivered or (self._halt is not None and self._halt.is_set()):
                        raise exc
                    else:
                        # The pool never started producing. Finish on this thread instead.
                        _shutdown_workers()
                        outcome = run_serial_search(
                            usable, avail, required, branches, min_len, max_words, max_results,
                            self._halt, self._user_stop, on_batch, on_progress,
                        )
            else:
                outcome = run_serial_search(
                    usable, avail, required, branches, min_len, max_words, max_results,
                    self._halt, self._user_stop, on_batch, on_progress,
                )
        except Exception as exc:
            outcome = "error"
            error = str(exc)
        finally:
            self._gui_q.put(("finished", gen, outcome, error))

    def stop_search(self) -> None:
        if not self._busy:
            return
        self._user_stop.set()
        if self._halt is not None:
            self._halt.set()
        _signal_cancel()
        self.status_label.config(text="Stopping...")
        self.stop_btn.config(state=tk.DISABLED)

    def _check_queue(self, gen: int) -> None:
        if self._closed or gen != self._gen:
            return
        finished = False
        pulses = 0
        try:
            while pulses < 30:
                message = self._gui_q.get_nowait()
                pulses += 1
                if message[1] != gen:
                    continue
                kind = message[0]
                if kind == "results":
                    self._append_phrases(message[2])
                elif kind == "progress":
                    self._progress_done = message[2]
                    self._progress_total = message[3]
                    if not self._user_stop.is_set():
                        self._refresh_search_status()
                elif kind == "status":
                    if not self._user_stop.is_set():
                        self.status_label.config(text=message[2])
                elif kind == "finished":
                    self._finish(message[2], message[3])
                    finished = True
                    break
        except queue.Empty:
            pass
        if finished or self._closed:
            return
        delay = 15 if pulses >= 30 else 40
        self.root.after(delay, lambda g=gen: self._check_queue(g))

    def _append_phrases(self, phrases: list[str]) -> None:
        if not phrases:
            return
        self.found_phrases.extend(phrases)
        self.results.config(state=tk.NORMAL)
        self.results.insert(tk.END, "\n".join(phrases) + "\n")
        self.results.see(tk.END)
        self.results.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.NORMAL)
        if not self._user_stop.is_set():
            self._refresh_search_status()

    def _refresh_search_status(self) -> None:
        found = len(self.found_phrases)
        total = self._progress_total
        if total:
            pct = 100.0 * self._progress_done / total
            self.progress["value"] = pct
            self.status_label.config(text=f"Searching ({found:,} found) — {pct:.0f}%")
        else:
            self.status_label.config(text=f"Searching ({found:,} found)")

    def _write_results(self, phrases: list[str]) -> None:
        self.results.config(state=tk.NORMAL)
        self.results.delete("1.0", tk.END)
        if phrases:
            self.results.insert(tk.END, "\n".join(phrases) + "\n")
        self.results.config(state=tk.DISABLED)

    def _finish(self, outcome: str, error: str | None) -> None:
        seen: set[str] = set()
        unique: list[str] = []
        for phrase in self.found_phrases:
            if phrase not in seen:
                seen.add(phrase)
                unique.append(phrase)
        unique.sort(key=_interest_key)
        self.found_phrases = unique
        self._write_results(self.found_phrases)
        found = len(self.found_phrases)
        self.save_btn.config(state=tk.NORMAL if found else tk.DISABLED)
        if outcome == "stopped":
            self.status_label.config(text=f"Stopped ({found:,} found)" if found else "Stopped")
        elif outcome == "limit":
            self.progress["value"] = 100
            self.status_label.config(
                text=f"Stopped at {found:,} results. Raise Max results to keep going."
            )
        elif outcome == "error":
            self.status_label.config(text="Error")
            messagebox.showerror("Fastagram", error or "Search failed.", parent=self.root)
        elif found:
            self.progress["value"] = 100
            self.status_label.config(text=f"Complete ({found:,} found)")
        else:
            self.progress["value"] = 100
            self.status_label.config(text="No anagrams found")
        self._set_busy(False)

    def save_anagrams(self) -> None:
        if not self.found_phrases:
            messagebox.showinfo("Fastagram", "No anagrams to save.", parent=self.root)
            return
        filepath = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Anagrams",
        )
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8") as handle:
                handle.write("\n".join(self.found_phrases) + "\n")
        except OSError as exc:
            messagebox.showerror("Fastagram", f"Could not save the file:\n{exc}", parent=self.root)
            return
        messagebox.showinfo("Fastagram", f"Anagrams saved to:\n{filepath}", parent=self.root)

    def clear_anagrams(self) -> None:
        if self._busy:
            return
        self.found_phrases = []
        self._write_results([])
        self.save_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.status_label.config(text=self._ready_status())

    def _on_close(self) -> None:
        self._closed = True
        self._user_stop.set()
        if self._halt is not None:
            self._halt.set()
        _shutdown_workers()
        self.root.destroy()


def main() -> None:
    path = dictionary_path()
    if not os.path.isfile(path):
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Fastagram",
            f"Dictionary file not found:\n{path}\n\nPlace words.txt in the same folder as the program.",
        )
        root.destroy()
        return
    try:
        load_dictionary(path)
    except (OSError, ValueError) as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Fastagram", f"Could not read the dictionary:\n{exc}")
        root.destroy()
        return
    root = tk.Tk()
    FastagramApp(root)
    root.mainloop()
    _shutdown_workers()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
