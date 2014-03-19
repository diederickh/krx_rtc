WebRTC Video Streaming
-----------------------
- Simple C library to stream video/audio using WebRTC
- Start with Video stream, Audio will be added later
- Keep dependencies low
- Cross platform; main development is Linux/Mac
- Video frame ingestion decoupled (e.g. any YUV buffer can be streamed)
- Input / output will be RTP packets

Sub-projects
-------------
- WebRTC Signaling (STUN, TURN, ICE)
- Encoding/Decoding video (libvpx), audio (libFLAC)
- RTP(S) / TLS

Flow:
-----

````

  webpage → sends sdp (offer) → [ our server ] 
     ↑                                ↓
         ← sends back sdp (offer) ←

````
