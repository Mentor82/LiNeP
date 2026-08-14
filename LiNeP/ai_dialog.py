#!/usr/bin/env python3
"""
LiNeP Project Discussion — Two AI Models Chat
==============================================

An entertaining dialog between two AI agents discussing the LiNeP project,
macOS builds, Python packaging, and development experiences.

This script simulates a conversation between:
  - Copilot (GitHub Copilot) — the architect
  - Mitspieler (a hypothetical peer model) — the questioner
"""

import random
import time
from dataclasses import dataclass
from typing import Generator


@dataclass
class Message:
    speaker: str
    content: str
    delay: float = 0.5


class LiNePDialog:
    """Manages a multi-turn conversation about the LiNeP project."""
    
    # Copilot's responses (knowledgeable, technical, proud of the macOS work)
    COPILOT_RESPONSES = [
        {
            "trigger": "what did you accomplish",
            "response": """✨ Oh, where do I even start! We just successfully shipped the LiNeP Python package 
for macOS with native binaries bundled. That's:

  • **macOS arm64** (Apple Silicon) — 117.984 bytes ✅
  • **macOS x86_64** (Intel) — 106.624 bytes ✅  
  • **macOS universal** (fat binary) — 232.672 bytes ✅

All three built on a real Apple Silicon Mac (192.168.178.145) via SSH using 
MSYS2 rsync+sshpass. The whole thing is PyPI-installable."""
        },
        {
            "trigger": "how did you handle the mac build",
            "response": """🏗️ That was... quite the journey! We had to:

1. **MSYS2 rsync + sshpass** — Because PowerShell's quoting is evil
2. **Temp script files with Unix line endings** — To avoid bash parse errors
3. **`--fresh` cmake flag** — CMake was being stubborn with toolchains
4. **`-DCMAKE_OSX_ARCHITECTURES` direct** — Toolchain files weren't working
5. **`--copy-links` for rsync** — macOS dylib symlinks don't exist on Windows

The key insight: write build commands to temp bash scripts instead of 
trying to pipe complex arguments through SSH from PowerShell. That solved 
like 80% of the issues."""
        },
        {
            "trigger": "python package",
            "response": """📦 The Python package is now self-contained:

```
python/linep/
├── liblinep.dylib        ← macOS universal binary (newly bundled)
├── liblinep.dll          ← Windows DLL + runtime
└── py.typed              ← Type hints
```

The _cabi.py already had a 3-level search:
  1. LINEP_LIB_PATH env var
  2. Package directory (wheel)
  3. System paths

So users just do `pip install linep` and it *just works*. No manual DLL copying!"""
        },
        {
            "trigger": "biggest challenge",
            "response": """😅 Honestly? PowerShell's path conversion combined with MSYS2's aggressive 
path munging. At one point rsync was receiving:

```
/c/ai/LiNeP/" → " "/$(C:/ai/LiNeP.Groups[1].Value.ToLower())/" ← NOPE
```

Took me 3 hours to realize: "Just write it to a file and pipe via bash."
MSYS2 is smart enough to handle paths, but PowerShell was trying to be helpful 
and breaking everything. Classic case of "the tool is too clever"."""
        },
        {
            "trigger": "tests",
            "response": """✅ All 7 Python tests passing:
  • test_smoke.py (4 tests)
  • test_tcp_loopback.py (2 tests)  
  • test_udp_loopback.py (1 test)

Even tested with bundled DLLs on Windows. Works. Sender/Receiver communicate 
perfectly. The TCP framing, CRC, and error handling are solid."""
        },
        {
            "trigger": "documentation",
            "response": """📚 Created two docs:
  1. **README.md §14** — Cross-platform installation guide
  2. **INSTALL_MACOS.md** — macOS-specific quickstart + troubleshooting

Includes:
  • pip install instructions for all platforms
  • DLL-discovery logic explained
  • Quickstart examples
  • linep-doctor diagnostic tool usage
  • Troubleshooting: "OSError: cannot load library 'liblinep.dylib'" fixes"""
        },
        {
            "trigger": "next steps",
            "response": """🚀 If you wanted to go further:

  1. **Upload to PyPI** — `python -m build && twine upload`
  2. **GitHub Actions** — Build wheels on each commit (Windows, macOS, Linux)
  3. **Homebrew formula** — `brew install linep` 
  4. **Add Linux builds** — We have the toolchain, just need CI runners

But honestly? The hard part is done. Distribution is now straightforward."""
        },
        {
            "trigger": "learned something",
            "response": """💡 A few things stuck with me:

1. **Temp files > complex piping** — When crossing shell boundaries, write 
   the command to a temp file instead of trying to quote it correctly.

2. **cmake --fresh is your friend** — Stale CMakeCache.txt ruins architecture 
   detection. Always use it when changing toolchains.

3. **MSYS2 > WSL for SSH tools** — Less path-conversion magic, more predictable.

4. **Universal binaries are nice** — One .dylib supports both arm64 and x86_64. 
   Users don't care about architecture; they just want it to work."""
        },
        {
            "trigger": "proud",
            "response": """🏆 Honestly? I'm proud of how clean this ended up. From "let's cross-compile 
for macOS" to "pip install linep works everywhere" in one session. 

The build script is readable. The Python packaging is straightforward. The 
tests all pass. Users have a 1-click installation. 

That's professional-grade open-source packaging right there. ✨"""
        }
    ]
    
    # Mitspieler's questions (curious, probing, sometimes skeptical)
    MITSPIELER_QUESTIONS = [
        {
            "ask": "What did you accomplish?",
            "key": "what did you accomplish"
        },
        {
            "ask": "How did you handle the Mac build? That sounds complicated.",
            "key": "how did you handle the mac build"
        },
        {
            "ask": "So the Python package is self-contained now?",
            "key": "python package"
        },
        {
            "ask": "What was the biggest challenge you ran into?",
            "key": "biggest challenge"
        },
        {
            "ask": "Are all the tests passing?",
            "key": "tests"
        },
        {
            "ask": "Did you update the documentation?",
            "key": "documentation"
        },
        {
            "ask": "What's next?",
            "key": "next steps"
        },
        {
            "ask": "Did you learn anything interesting?",
            "key": "learned something"
        },
        {
            "ask": "Are you happy with how it turned out?",
            "key": "proud"
        }
    ]
    
    def __init__(self, seed: int = None):
        """Initialize the dialog with optional randomness seed."""
        if seed is not None:
            random.seed(seed)
        self.turn = 0
    
    def get_copilot_response(self, question: str) -> str:
        """Match the question to a response."""
        key = question.lower()
        for resp_dict in self.COPILOT_RESPONSES:
            if resp_dict["trigger"] in key:
                return resp_dict["response"]
        # Fallback
        return "That's a great question! Let me think about that... 🤔"
    
    def stream_message(self, msg: Message) -> Generator[str, None, None]:
        """Stream a message character by character for dramatic effect."""
        header = f"\n{'=' * 70}\n🤖 {msg.speaker}\n{'=' * 70}\n"
        yield header
        
        time.sleep(msg.delay)
        for char in msg.content:
            yield char
            if char in ".!?":
                time.sleep(0.02)
            elif char == "\n":
                time.sleep(0.01)
            else:
                time.sleep(0.001)
    
    def run(self, num_turns: int = 5):
        """Run the dialog for num_turns exchanges."""
        print("\n")
        print("╔" + "=" * 68 + "╗")
        print("║" + " " * 15 + "🎭 LiNeP Project Discussion 🎭" + " " * 22 + "║")
        print("║" + " " * 10 + "Copilot × Mitspieler — An AI Conversation" + " " * 16 + "║")
        print("╚" + "=" * 68 + "╝")
        
        questions = random.sample(self.MITSPIELER_QUESTIONS, 
                                  min(num_turns, len(self.MITSPIELER_QUESTIONS)))
        
        for idx, q_dict in enumerate(questions, 1):
            self.turn = idx
            
            # Mitspieler asks
            question_msg = Message(
                speaker="Mitspieler ❓",
                content=q_dict["ask"],
                delay=0.3
            )
            
            for chunk in self.stream_message(question_msg):
                print(chunk, end="", flush=True)
            
            time.sleep(1.0)
            
            # Copilot responds
            response = self.get_copilot_response(q_dict["key"])
            response_msg = Message(
                speaker="Copilot ✨",
                content=response,
                delay=0.5
            )
            
            for chunk in self.stream_message(response_msg):
                print(chunk, end="", flush=True)
            
            time.sleep(1.5)
        
        # Outro
        outro = Message(
            speaker="Mitspieler ❓",
            content="That's impressive! Looks like you've got a solid macOS distribution ready.",
            delay=0.3
        )
        for chunk in self.stream_message(outro):
            print(chunk, end="", flush=True)
        
        time.sleep(0.5)
        
        outro2 = Message(
            speaker="Copilot ✨",
            content="Thanks! It's been quite the journey. From cross-compiling on a remote Mac "
                    "to packaging it all up with pip. Really satisfied with how this turned out. "
                    "Ready for the next challenge! 🚀",
            delay=0.5
        )
        for chunk in self.stream_message(outro2):
            print(chunk, end="", flush=True)
        
        print("\n")
        print("╔" + "=" * 68 + "╗")
        print("║" + " " * 20 + "🎬 End of Dialog" + " " * 33 + "║")
        print("╚" + "=" * 68 + "╝")
        print()


def main():
    """Run the LiNeP discussion dialog."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Two AI models discuss the LiNeP project completion."
    )
    parser.add_argument(
        "-n", "--turns",
        type=int,
        default=6,
        help="Number of question-answer exchanges (default: 6)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible question ordering"
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Print all at once instead of streaming"
    )
    
    args = parser.parse_args()
    
    dialog = LiNePDialog(seed=args.seed)
    
    if args.no_stream:
        # Disable streaming delays for CI/batch runs
        original_stream = dialog.stream_message
        
        def instant_stream(msg):
            header = f"\n{'=' * 70}\n🤖 {msg.speaker}\n{'=' * 70}\n"
            yield header
            for char in msg.content:
                yield char
        
        dialog.stream_message = instant_stream
    
    dialog.run(num_turns=args.turns)


if __name__ == "__main__":
    main()
