# LiNeP — macOS Installation

Schnelle Installationsanleitung für das LiNeP Python-Paket auf macOS.

## Installation (vom PyPI)

```bash
# 1. Erstelle ein virtuelles Environment
python3 -m venv linep_env
source linep_env/bin/activate

# 2. Installiere das Paket (mit gebündeltem dylib)
pip install linep

# 3. Verifiziere die Installation
python3 << 'EOF'
import linep
print(f"✓ LiNeP {linep.__version__} installed")
print(f"✓ C-ABI library loaded successfully")
EOF
```

## Lokale Installation (aus dem Repository)

```bash
cd LiNeP/python

# 1. Venv erstellen
python3 -m venv .venv
source .venv/bin/activate

# 2. Installiere editierbar (mit Development-Tools)
pip install -e ".[dev]"

# 3. Tests ausführen
python -m pytest -q tests/
# Erwartet: 7 passed in ~0.2s
```

## Fehlerbehandlung

### "ModuleNotFoundError: No module named 'linep'"

```bash
# Stelle sicher, dass das venv aktiviert ist
source linep_env/bin/activate

# Oder installiere global (nicht empfohlen)
pip install --break-system-packages linep
```

### "OSError: cannot load library 'liblinep.dylib'"

```bash
# Option A: Library im Systemverzeichnis installieren
brew install liblinep  # (falls über Homebrew verfügbar)

# Option B: Manuelle Kopie ins System-Verzeichnis
sudo cp build-macos-universal/liblinep.dylib /usr/local/lib/
sudo install_name_tool -id /usr/local/lib/liblinep.dylib /usr/local/lib/liblinep.dylib

# Option C: LD_LIBRARY_PATH setzen (temporär)
export DYLD_LIBRARY_PATH=$(pwd)/build-macos-universal:$DYLD_LIBRARY_PATH

# Option D: Expliziter Pfad via Umgebungsvariable
export LINEP_LIB_PATH=$(pwd)/build-macos-universal/liblinep.dylib
python3 -c "import linep; print('OK')"
```

## Schnellstart

```python
#!/usr/bin/env python3
import linep
from linep import Sender, Receiver, TaskType

linep.net_init()

# Echo-Handler
def handler(task_type, correlation_id, worker_id, slot_id, payload):
    print(f"  Received: {payload.decode('utf-8', errors='ignore')}")
    return linep.ResultStatus.OK, b"Echo: " + payload

# Starte einen Receiver (Port 9000 TCP, 9001 UDP)
with Receiver() as recv:
    recv.start(port=9000, handler=handler)
    import time
    time.sleep(0.1)
    
    # Sende eine Task
    with Sender() as sender:
        result = sender.send_task(
            host="127.0.0.1",
            port=9000,
            task_type=TaskType.INSTRUCT,
            payload=b"Hello macOS",
            timeout_ms=2000,
        )
        print(f"  Status: {result.status}")
        print(f"  Response: {result.body.decode('utf-8', errors='ignore')}")

linep.net_cleanup()
```

## linep-doctor — Diagnose-Tool

Das Paket enthält ein Diagnosetool zum Prüfen, ob alles funktioniert:

```bash
# Teste DLL-Laden + UDP-Loopback (kein Server nötig)
linep-doctor --host 127.0.0.1 --tcp-port 9000 --udp-port 9001 --skip-tcp

# Teste TCP-Konnektivität zu einem echten Server
linep-doctor --host 192.168.1.100 --tcp-port 9000 --udp-port 9001

# Nur DLL prüfen
linep-doctor --skip-tcp --skip-udp
```

## Unterstützte Architekturen

| Architektur | Status |
|---|---|
| Apple Silicon (arm64) | ✅ Unterstützt (im universal binary) |
| Intel (x86_64) | ✅ Unterstützt (im universal binary) |
| Universal (arm64 + x86_64) | ✅ Single fat binary |

Prüfe deine Architektur mit:

```bash
uname -m
# arm64       → Apple Silicon
# x86_64      → Intel Mac
```

## Weitere Ressourcen

- [Hauptdokumentation](README.md) — Protokoll-Details, C++-Build, etc.
- [Python-Paket Dokumentation](README.md#14-python-paket-) — Detaillierte API
- [Tests](python/tests/) — Beispiele für Sender/Receiver

---

**Version**: LiNeP 1.0.0  
**Python**: 3.9+  
**macOS**: 11.0+ (mit Apple Silicon und Intel Support)
