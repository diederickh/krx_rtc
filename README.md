KRX_RTC
-------

Research library that enables WebRTC input/output. We're aiming 
to create a twofold library. The described input/output features 
are reversable for both parts. 

__Part 1: ICE__

It will handle the signaling and ICE to create an answer/offer 
SDP which can be shared on any separate signaling channel. As experiment 
and ease of development this package contains a basic https server 
that can be used to exchange SDP offer/answer messages. These features 
are used by the javascript/test projects.

    input: offer SDP from e.g. browser 
    output: answer SDP from our library based on ice 

__Part 2: SRTP/RTP__ (+ test rtp protocol handlers, e.g. vp8, opus)

We handle incoming SRTP data, once the the offer/answer have been exchanged. 
When the offer/answer have been exhanged the WebRTC peers will start the DTLS 
handshake after which the exchange of SRTP takes place. The SRTP data will 
be the input for this library and the output will be RTP packets. For testing 
purposes we will implement a couple of RTP specific parsers to make sure we're 
parsing the incoming packets correctly, these "test" parsers will be a separate 
lib that accepts raw RTP packets and does w/e it needs to do to be able to 
validate the parsing process. 

    input: srtp packets 
    output: rtp packets


