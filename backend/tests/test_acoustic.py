import io
import math
import struct
import wave
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.acoustic import signature,similarity
from app.main import app

def tone(freq,amplitude=12000,seconds=3):
    buffer=io.BytesIO()
    with wave.open(buffer,"wb") as wav:
        wav.setparams((1,2,8000,0,"NONE","not compressed"))
        wav.writeframes(struct.pack("<"+"h"*(8000*seconds),*(int(amplitude*math.sin(2*math.pi*freq*i/8000)) for i in range(8000*seconds))))
    return buffer.getvalue()

def test_spectral_comparison():
    reference=signature(tone(400))
    assert similarity(signature(tone(400,6000)),reference)>.99
    assert similarity(signature(tone(800)),reference)<.2
    with pytest.raises(HTTPException):
        signature(tone(400,0))
    with pytest.raises(HTTPException):
        signature(b"not a wav")

def test_routes():
    assert TestClient(app).post("/api/v1/acoustic/match",content=b"",headers={"Content-Type":"audio/wav"}).status_code==401
