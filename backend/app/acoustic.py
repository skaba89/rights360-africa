"""Experimental spectral signature for short PCM WAV excerpts."""
import io
import math
import wave
import struct
from fastapi import HTTPException

MAX_BYTES=480044
RATE=8000
FRAME=800
HOP=400
# Goertzel bands, independent of absolute signal amplitude.
BINS=(10,15,20,25,30,40,50,60,80,100,120,150,180,220,260,300)
COEFF=[2*math.cos(2*math.pi*k/FRAME) for k in BINS]
WINDOW=[0.5-0.5*math.cos(2*math.pi*i/(FRAME-1)) for i in range(FRAME)]

def signature(data):
    if len(data)>MAX_BYTES: raise HTTPException(413,"Audio too large")
    try:
        with wave.open(io.BytesIO(data),"rb") as w:
            n=w.getnframes()
            if w.getnchannels()!=1 or w.getsampwidth()!=2 or w.getframerate()!=RATE or w.getcomptype()!="NONE" or not 3*RATE<=n<=30*RATE:
                raise ValueError()
            raw=w.readframes(n)
            if len(raw)!=2*n: raise ValueError()
    except (wave.Error,EOFError,ValueError,struct.error):
        raise HTTPException(422,"Expected mono PCM16 WAV, 8 kHz, 3–30 seconds") from None
    samples=struct.unpack("<"+"h"*n,raw)
    result=[]
    for start in range(0,n-FRAME+1,HOP):
        frame=[samples[start+i]*WINDOW[i] for i in range(FRAME)]
        if sum(x*x for x in frame)/FRAME<10000:
            result.append(None)
            continue
        powers=[]
        for coeff in COEFF:
            a=z=0.0
            for sample in frame:
                a,z=sample+coeff*a-z,a
            powers.append(max(0,a*a+z*z-coeff*a*z))
        norm=math.sqrt(sum(p*p for p in powers))
        result.append([round(p/norm,5) for p in powers] if norm else None)
    if sum(x is not None for x in result)<40:
        raise HTTPException(422,"Insufficient audible signal")
    return result

def similarity(query,reference):
    # Require at least 80% query coverage and 40 informative aligned frames.
    best=0.0
    for offset in range(-len(query)//5,len(reference)-4*len(query)//5+1):
        scores=[]
        for i,q in enumerate(query):
            j=i+offset
            if q is not None and 0<=j<len(reference) and reference[j] is not None:
                scores.append(sum(a*b for a,b in zip(q,reference[j])))
        if len(scores)>=max(40,math.ceil(.8*len(query))):
            best=max(best,sum(scores)/len(scores))
    return min(1.0,best)
