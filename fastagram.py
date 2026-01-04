# Fastagram - fastish anagram finder
# written by no1453@gmail.com
# Michael Hoskins 2026.01.03

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from collections import Counter
from typing import List
import os
import threading
import queue
import string
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# ----------------------------- Dictionary Loading -----------------------------
DICTIONARY_PATH = "words.txt"
if not os.path.exists(DICTIONARY_PATH):
    raise FileNotFoundError(f"Dictionary file '{DICTIONARY_PATH}' not found.")

with open(DICTIONARY_PATH, encoding="utf-8") as f:
    WORD_LIST = [line.strip().lower() for line in f if line.strip()]

WORD_COUNTERS = [Counter(word) for word in WORD_LIST]


def find_possible_words(letters: str) -> List[str]:
    available = Counter(letters.lower())
    possibles = []
    for i, word_count in enumerate(WORD_COUNTERS):
        if all(word_count[c] <= available[c] for c in word_count):
            possibles.append(WORD_LIST[i])
    possibles.sort(key=len, reverse=True)
    return possibles


# Top-level worker functions for multiprocessing
def mp_process_chunk(args):
    chunk_start, chunk_end, remaining_dict, sorted_candidates, candidate_counters, initial_words = args
    remaining = Counter(remaining_dict)
    local_results = []
    for i in range(chunk_start, chunk_end):
        word = sorted_candidates[i]
        word_count = candidate_counters[i]
        if all(word_count[c] <= remaining[c] for c in word_count):
            new_remaining = remaining - word_count
            mp_backtrack(initial_words + [word], new_remaining, i, local_results, sorted_candidates, candidate_counters)
    return local_results


def mp_backtrack(current_words: List[str], remaining: Counter, min_idx: int, local_results: List[str], sorted_candidates: List[str], candidate_counters: List[Counter]):
    if sum(remaining.values()) == 0:
        phrase = " ".join(sorted(current_words))
        local_results.append(phrase)
        return

    for i in range(min_idx, len(sorted_candidates)):
        word_count = candidate_counters[i]
        if all(word_count[c] <= remaining[c] for c in word_count):
            new_remaining = remaining - word_count
            mp_backtrack(current_words + [sorted_candidates[i]], new_remaining, i, local_results, sorted_candidates, candidate_counters)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    # ----------------------------------- GUI Setup -----------------------------------
    root = tk.Tk()
    root.title("Fastagram - Fast Anagram Finder")
    root.geometry("800x700")
    root.configure(padx=10, pady=10, bg="#1e1e1e")

    BG = "#1e1e1e"
    FG = "#dddddd"
    ENTRY_BG = "#333333"
    TEXT_BG = "#252525"
    SELECT_BG = "#007acc"

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("TButton", background=BG, foreground=FG)
    style.map("TButton", background=[('active', SELECT_BG)], foreground=[('active', 'white')])
    style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=FG)
    style.configure("TProgressbar", background=SELECT_BG, troughcolor=BG)

    top_controls = ttk.Frame(root)
    top_controls.pack(fill=tk.X, pady=(0, 10))
    top_frame = ttk.Frame(top_controls)
    top_frame.pack(fill=tk.X)

    ttk.Label(top_frame, text="String to be anagrammed:").grid(row=0, column=0, sticky=tk.W, pady=2)
    letters_entry = ttk.Entry(top_frame, width=50)
    letters_entry.grid(row=1, column=0, columnspan=3, sticky=tk.EW, pady=2)

    ttk.Label(top_frame, text="Required word:").grid(row=2, column=0, sticky=tk.W, pady=2)
    required_entry = ttk.Entry(top_frame, width=50)
    required_entry.grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=2)

    top_frame.columnconfigure(0, weight=1)

    btn_frame = ttk.Frame(root)
    btn_frame.pack(fill=tk.X, pady=10)

    cached_possible_words: List[str] = []
    cached_letters: str = ""

    def validate_letters_input(s: str) -> bool:
        if not s:
            return False
        return all(c in string.ascii_letters for c in s)

    def show_possible_words():
        global cached_possible_words, cached_letters
        raw_letters = letters_entry.get()
        if not raw_letters:
            messagebox.showwarning("Input Error", "Please enter letters.")
            return
        if not validate_letters_input(raw_letters):
            messagebox.showerror("Invalid Input", "Only letters allowed.")
            return

        letters = raw_letters.replace(" ", "").lower()
        cached_possible_words = find_possible_words(letters)
        cached_letters = letters
        display_words = sorted(cached_possible_words)
        words_listbox.delete(0, tk.END)
        for word in display_words:
            words_listbox.insert(tk.END, word)

    def clear_inputs():
        letters_entry.delete(0, tk.END)
        required_entry.delete(0, tk.END)
        global cached_possible_words, cached_letters
        cached_possible_words = []
        cached_letters = ""
        words_listbox.delete(0, tk.END)

    def on_word_select(event):
        selection = words_listbox.curselection()
        if selection:
            word = words_listbox.get(selection[0])
            current = required_entry.get().strip()
            if current:
                required_entry.insert(tk.END, " " + word)
            else:
                required_entry.delete(0, tk.END)
                required_entry.insert(0, word)

    ttk.Button(btn_frame, text="Find Possible Words", command=show_possible_words).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Clear Inputs", command=clear_inputs).pack(side=tk.LEFT, padx=5)

    progress_frame = ttk.Frame(root)
    progress_frame.pack(fill=tk.X, pady=10)
    progress = ttk.Progressbar(progress_frame, mode='determinate', length=400)  # Changed to determinate
    progress.pack(side=tk.LEFT, expand=True, fill=tk.X)
    status_label = ttk.Label(progress_frame, text="Ready", foreground="#aaaaaa")
    status_label.pack(side=tk.RIGHT, padx=10)

    result_queue = queue.Queue()
    search_thread: threading.Thread | None = None
    stop_event = threading.Event()
    found_count = 0

    def start_anagram_search():
        global search_thread, cached_possible_words, cached_letters, found_count

        if search_thread and search_thread.is_alive():
            messagebox.showwarning("Search in Progress", "A search is already running.")
            return

        raw_letters = letters_entry.get()
        if not raw_letters:
            messagebox.showwarning("Input Error", "Please enter letters.")
            return
        if not validate_letters_input(raw_letters):
            messagebox.showerror("Invalid Input", "Only letters allowed.")
            return

        letters = raw_letters.replace(" ", "").lower()
        required_raw = required_entry.get().strip()
        required = required_raw.lower()

        if required and not validate_letters_input(required_raw.replace(" ", "")):
            messagebox.showerror("Invalid Input", "Required word(s) only letters.")
            return

        if letters != cached_letters:
            cached_possible_words = find_possible_words(letters)
            cached_letters = letters
            display_words = sorted(cached_possible_words)
            words_listbox.delete(0, tk.END)
            for word in display_words:
                words_listbox.insert(tk.END, word)

        stop_event.clear()
        result_queue.queue.clear()
        found_count = 0

        anagrams_text.config(state=tk.NORMAL)
        anagrams_text.delete(1.0, tk.END)
        anagrams_text.insert(tk.END, "Searching...\n")
        anagrams_text.config(state=tk.DISABLED)
        status_label.config(text="Initializing...")

        letters_entry.config(state=tk.DISABLED)
        required_entry.config(state=tk.DISABLED)
        find_anagrams_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)

        progress['value'] = 0

        def run_multicore_search():
            global found_count
            try:
                remaining = Counter(letters)
                initial_words = required.split() if required else []
                if required:
                    req_count = Counter(required.replace(" ", ""))
                    if not all(req_count[c] <= remaining[c] for c in req_count):
                        result_queue.put(("error", "Required word cannot be formed."))
                        result_queue.put(("finished", None))
                        return
                    remaining -= req_count

                sorted_candidates = sorted(cached_possible_words)
                candidate_counters = [Counter(word) for word in sorted_candidates]

                total_chunks = len(sorted_candidates)
                if total_chunks == 0:
                    result_queue.put(("done", None))
                    result_queue.put(("finished", None))
                    return

                num_workers = os.cpu_count() or 4
                chunk_size = max(1, total_chunks // num_workers)
                chunks = []
                for i in range(0, total_chunks, chunk_size):
                    end = min(i + chunk_size, total_chunks)
                    chunks.append((i, end, dict(remaining), sorted_candidates, candidate_counters, initial_words))

                completed = 0
                with ProcessPoolExecutor(max_workers=num_workers) as executor:
                    futures = [executor.submit(mp_process_chunk, chunk) for chunk in chunks]
                    for future in as_completed(futures):
                        if stop_event.is_set():
                            executor.shutdown(wait=False)
                            break
                        chunk_results = future.result()
                        completed += 1
                        result_queue.put(("progress", completed / len(chunks) * 100))
                        for phrase in chunk_results:
                            found_count += 1
                            result_queue.put(("result", phrase))
                            result_queue.put(("count", found_count))

                result_queue.put(("done", None))

            except Exception as e:
                result_queue.put(("error", str(e)))
            finally:
                result_queue.put(("finished", None))

        search_thread = threading.Thread(target=run_multicore_search)
        search_thread.start()
        check_queue()

    def stop_search():
        stop_event.set()
        progress['value'] = 0
        status_label.config(text="Search stopped")
        enable_inputs()

    def enable_inputs():
        letters_entry.config(state=tk.NORMAL)
        required_entry.config(state=tk.NORMAL)
        find_anagrams_btn.config(state=tk.NORMAL)
        stop_btn.config(state=tk.DISABLED)

    def check_queue():
        try:
            processed_any = False
            while True:
                msg_type, content = result_queue.get_nowait()
                processed_any = True

                if msg_type == "result":
                    anagrams_text.config(state=tk.NORMAL)
                    if anagrams_text.get(1.0, tk.END).strip() == "Searching...":
                        anagrams_text.delete(1.0, tk.END)
                    anagrams_text.insert(tk.END, content + "\n")
                    anagrams_text.see(tk.END)
                    anagrams_text.config(state=tk.DISABLED)

                elif msg_type == "count":
                    status_label.config(text=f"Searching ({content} found)")

                elif msg_type == "progress":
                    progress['value'] = content
                    status_label.config(text=f"Searching ({found_count} found) – {content:.1f}%")

                elif msg_type == "error":
                    anagrams_text.config(state=tk.NORMAL)
                    anagrams_text.delete(1.0, tk.END)
                    anagrams_text.insert(tk.END, f"Error: {content}\n")
                    anagrams_text.config(state=tk.DISABLED)
                    status_label.config(text="Error")

                elif msg_type in ("done", "finished"):
                    progress['value'] = 100
                    enable_inputs()
                    if msg_type == "done":
                        anagrams_text.config(state=tk.NORMAL)
                        current_text = anagrams_text.get(1.0, tk.END).strip()
                        if current_text == "Searching...":
                            anagrams_text.delete(1.0, tk.END)
                            anagrams_text.insert(tk.END, "No anagrams found.\n")
                            status_label.config(text="No anagrams found")
                        else:
                            anagrams_text.insert(tk.END, "\nSearch complete.\n")
                            status_label.config(text=f"Complete ({found_count} found)")
                        anagrams_text.config(state=tk.DISABLED)
                    return

        except queue.Empty:
            if processed_any:
                root.after(100, check_queue)
            else:
                root.after(100, check_queue)

    find_anagrams_btn = ttk.Button(btn_frame, text="Find Anagrams", command=start_anagram_search)
    find_anagrams_btn.pack(side=tk.LEFT, padx=5)
    stop_btn = ttk.Button(btn_frame, text="Stop Search", command=stop_search, state=tk.DISABLED)
    stop_btn.pack(side=tk.LEFT, padx=5)

    ttk.Label(root, text="Possible words (click to add to required):").pack(anchor=tk.W)
    words_frame = ttk.Frame(root)
    words_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))
    words_listbox = tk.Listbox(words_frame, height=10, exportselection=False, bg=TEXT_BG, fg=FG, selectbackground=SELECT_BG)
    words_scroll = ttk.Scrollbar(words_frame, orient=tk.VERTICAL, command=words_listbox.yview)
    words_listbox.configure(yscrollcommand=words_scroll.set)
    words_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    words_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    words_listbox.bind("<<ListboxSelect>>", on_word_select)
    ttk.Button(root, text="Clear Possible Words", command=lambda: words_listbox.delete(0, tk.END)).pack(anchor=tk.W, pady=2)

    ttk.Label(root, text="Anagrams (appear as found):").pack(anchor=tk.W)
    anagrams_text = scrolledtext.ScrolledText(root, height=15, state=tk.DISABLED, wrap=tk.WORD, bg=TEXT_BG, fg=FG)
    anagrams_text.pack(fill=tk.BOTH, expand=True)
    ttk.Button(root, text="Clear Anagrams",
               command=lambda: [anagrams_text.config(state=tk.NORMAL), anagrams_text.delete(1.0, tk.END), anagrams_text.config(state=tk.DISABLED)]).pack(anchor=tk.W, pady=2)

    root.mainloop()

