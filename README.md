# Patchrrr

Patchrrr is a minimalist Python based patchbay for Jack audio and ALSA MIDI on Linux. It takes lists of input/output pairs and tries to keep them connected at all times.

This project was created for a headless audio processing setup, with no X or Wayland present.

### Features

* 800 lines of Python with no dependencies (thanks to `ctypes`)
* Easy install — just download the single file
* Linux only

### Maybe future features

* Dynamic patching, including the ability to disconnect clients
* Run in the background so the main thread isn't blocked
* Support for Jack MIDI (assuming it doesn't just work already)

## Install

```
uv pip install git+https://github.com/scottyeager/patchrrr.git
```

Or for a quick and dirty option, just copy the one .py file.

## Usage

Run standalone by editing the connection lists at the top of `patchrrr.py`, then:

```
python patchrrr.py
```

Or import it and pass your own connections:

```python
from patchrrr import PatchrrrManager

manager = PatchrrrManager(
    alsa_connections=[
        ("My App:output", "My Synth:input"),
    ],
    jack_connections=[
        ("app:out_1", "system:playback_1"),
    ],
)
manager.start()
```

When embedding in a larger application, pass `install_signals=False` to prevent patchrrr from overriding your signal handlers, then set `manager.running = False` to stop it.

## Notes

Patchrrr is designed around blocking IO, threads, and queues. It should be fairly lightweight in terms of resource consumption, but running super fast isn't the main goal.
