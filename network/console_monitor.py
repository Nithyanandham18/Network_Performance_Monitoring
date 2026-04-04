"""
console_monitor.py
===================
Thin wrapper — just runs behavioral_classifier.py's main loop.
All three stages (classifier + degradation + root cause) are
already wired inside behavioral_classifier.run().
"""

from behavioral_classifier import run

if __name__ == "__main__":
    run()