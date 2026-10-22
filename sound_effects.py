#!/usr/bin/env python3
"""sound_effects.py - Sintetizador nativo de efectos de sonido y alertas para Web-Sec.
Genera beeps táctiles y alarmas de contra-vigilancia usando síntesis matemática PCM con aplay/paplay.
"""

import math
import struct
import subprocess
import shutil
import threading

def _play_pcm(frequency: float, duration_s: float, volume: float = 0.3):
    sample_rate = 44100
    total_samples = int(sample_rate * duration_s)
    raw_data = bytearray()
    
    for i in range(total_samples):
        # Onda senoidal pura con decaimiento elástico
        t = float(i) / sample_rate
        decay = math.exp(-3.0 * (t / duration_s))
        sample = volume * decay * math.sin(2.0 * math.pi * frequency * t)
        val = int(sample * 32767.0)
        raw_data.extend(struct.pack("<h", val))

    aplay = shutil.which("aplay")
    if aplay:
        try:
            subprocess.run(
                [aplay, "-q", "-f", "S16_LE", "-r", str(sample_rate), "-c", "1"],
                input=raw_data,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
        except Exception:
            pass

def play_alert_detected():
    """Alarma bitonal de detección / Honeytoken disparado (Sonido de Emergencia)."""
    def _run():
        for _ in range(2):
            _play_pcm(880.0, 0.12, 0.4)
            _play_pcm(440.0, 0.15, 0.4)
    threading.Thread(target=_run, daemon=True).start()

def play_shield_on():
    """Beep de confirmación positiva (Escudos activos)."""
    def _run():
        _play_pcm(523.25, 0.08, 0.25) # C5
        _play_pcm(659.25, 0.10, 0.25) # E5
        _play_pcm(783.99, 0.15, 0.25) # G5
    threading.Thread(target=_run, daemon=True).start()

def play_burn_sequence():
    """Sonido descendente de purga de emergencia / Burn sequence."""
    def _run():
        freqs = [800, 600, 400, 200, 100]
        for f in freqs:
            _play_pcm(f, 0.06, 0.35)
    threading.Thread(target=_run, daemon=True).start()

if __name__ == "__main__":
    print("Probando sonido de alerta...")
    play_alert_detected()
