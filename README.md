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

## Usage

Just copy or download the `patchrrr.py` file. You can then use it in two ways:

1. Edit the examples at the top to specify the clients you want to patch together, then run:
```
python patchrrr.py
```
2. Import `patchrrr` into your own file and create an instance of the manager class

## Notes

Patchrrr is designed around blocking IO, threads, and queues. It should be fairly lightweight in terms of resource consumption, but running super fast isn't the main goal.
