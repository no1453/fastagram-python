Starting from a simple console-based program, it has developed a GUI version in python.

Usage is simple, type in a string to anagram (no spaces).   Optionally, add a word required to be in the anagram.
(Must actually be in the anagram string letters!)
You can click "Find words", and then click on a word on the list to add it to the "required word(s)".
Finally, click "Find Anagrams"

Note: when your string to be anagrammed starts to aproach 15 or more letters, it has a huge word space to explore,
so it may appear to freeze.   If left to work it will eventually finish.
So shorter strings to anagram, or requiring a word, will keep it more manageable, but it can finish longer jobs.

------------

Note on the "words" list: must be in the same directory as the .exe or .py script.   It contains an alphebetized
list of possible English words to consider.   I've been working on weeding out proper names, achaic terms,
excessively technical terms, and other such "word detrius".   It is a work in progress.
If you want to edit it yourself, it's just one word per line, each line ended by a newline character, no punctuation.
