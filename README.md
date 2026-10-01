# Fastagram

Fastagram finds anagrams of a word or phrase. It started as a console program and now runs in a window. Written by Michael Hoskins.

## Running

From this folder:

```
python fastagram.py
```

Python 3 is enough. The window uses tkinter, which comes with the official Windows installer. `words.txt` has to sit in the same folder as `fastagram.py`. If that file is missing, the program shows a message and exits.

## Finding an anagram

Type the letters or phrase to anagram. Capitals, spaces, and punctuation are ignored, and only the letters a–z are used.

Required words are optional. Separate them with spaces. Each of those words has to be spellable from the source letters. They are always kept, even when they are shorter than Min length, and they do not have to be in the dictionary. When the required words already use every letter, that phrase is the result.

**Find Possible Words** lists dictionary words that can be spelled from the source and meet Min length. Double-click a word, or select it and click **Add to Required**, to append it to Required words.

**Find Anagrams** searches for phrases that use every letter. Pressing Enter in either text box does the same thing. Phrases with fewer words come first. The words inside each phrase are shown in alphabetical order, so the same phrase appears once. **Save Anagrams** writes the phrases to a text file, one per line.

**Stop Search**, or the Escape key, cancels a running search. Closing the window cancels it too.

**Clear Inputs** clears both text boxes and the possible-word list. **Clear Required**, **Clear Possible Words**, and **Clear Anagrams** each clear only that part.

## Limits

| Control | Default | Range | Effect |
| --- | --- | --- | --- |
| Min length | 3 | 1–15 | Skips shorter dictionary words. Required words are still kept. |
| Max words | 10 | 1–30 | Longest phrase to build, counting the required words. If those words already reach the limit and letters remain, the search does not start. |
| Max results | 5000 | 1–100000 | Stops after this many phrases. |

## Word lists

Both lists use the same format: one word per line, letters a–z only, no punctuation. Blank lines are skipped. You can edit either file in a text editor.

- `words.txt` is the everyday list. **Common words only** is checked by default and searches this file.
- `words-all.txt` is the full list, including rare, archaic, and technical words. Uncheck **Common words only** to search it. Switching lists clears the current possible words and anagrams. If `words-all.txt` is not in the folder, the box stays on the everyday list.

The everyday list is the ordinary part of the full list. Ordinary seven-letter words were added to both files, because the original list had almost none. Proper names, archaic words, and overly technical terms are still being weeded out of the full list.

## Longer phrases

A source of about 15 letters or more has a very large search space. The window stays responsive, and Stop Search will halt the run, but it can still take a long time. A required word, a higher Min length, or a lower Max words or Max results keeps the search smaller. Very large searches also split the work across processors.
