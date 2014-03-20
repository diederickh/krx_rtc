/*

 WebRTC
 ------

 Very basic and limited webrtc code that is used to debug/test
 krx_rtc. Open this file in Firefox only for now. 

*/
navigator.getUserMedia = navigator.getUserMedia 
                         || navigator.webkitGetUserMedia
                         || navigator.mozGetUserMedia;

window.RTCPeerConnection = window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
window.RTCSessionDescription = window.mozRTCSessionDescription || window.RTCSessionDescription;

var vid_input = null;
var vid_output = null;
var pc_sender = null;
var pc_receiver = null;
var sdp_input = null; /* the sdp input texturea */
var sdp_output = null; /* the sdp output textarea */

function krx_init() {
  
  vid_input = $('#input_video')[0];
  vid_output = $('#output_video')[0];
  sdp_input = $('#video_input_sdp');
  sdp_output = $('#video_output_sdp');

  // ice servers
  var servers = {
    iceServers: [
        {url: "stun:stun.l.google.com:19302"},
    ]
  }

  // peer connections. sender initiates the connection, 
  pc_sender = new window.RTCPeerConnection(servers);
  pc_sender.onicecandidate = function(evt) {
    console.log("onicecandidate");
  };
  
  // receiver peer connection
  pc_receiver = new window.RTCPeerConnection(servers);
  pc_receiver.onaddstream = function(e) {

    if(navigator.mozGetUserMedia) { 
      vid_output.mozSrcObject = e.stream;
    }

    if(window.webkitURL) {
      vid_output.src = webkitURL.createObjectURL(e.stream);
    }

    vid_output.play();
  }

  // user media callbacks
  var krx_gum_success = function(stream) {

   
    if(navigator.mozGetUserMedia) {
      vid_input.mozSrcObject = stream;
    }

    if(window.webkitURL) {
      vid_input.src = webkitURL.createObjectURL(stream);
    }

    vid_input.play();

    pc_sender.addStream(stream);

    // load the SDP 
    pc_sender.createOffer(
      function(desc) {
        sdp_input.text(desc.sdp);
      },
      function(err) {
        console.log(err.message);
      }
   );
  };

  var krx_gum_error = function(err) {
    console.log(err);
  };

  // kickoff
  $("#init_gum_input").click(function() {
    navigator.getUserMedia({video:true}, krx_gum_success, krx_gum_error);
  });

  $('#start_streaming').click(function(){

    // get sdp from textarea
    var input_sdp_val = sdp_input.text();
    if(input_sdp_val.length == 0) {
      console.log("No sdp text found.");
      return;
    }
    sdp_output.text(input_sdp_val);

    // set the offer SDPs
    var isdp = new window.RTCSessionDescription({type:"offer", sdp:input_sdp_val});
    pc_receiver.setRemoteDescription(isdp);
    pc_sender.setLocalDescription(isdp);

    // set the answer SDPs
    pc_receiver.createAnswer(
      function(desc) {
        pc_sender.setRemoteDescription(desc);
        pc_receiver.setLocalDescription(desc);
      },
      function(err) {
        console.log(err.message);
      }
    );
  });
}


$(document).ready(function() {
  krx_init();
});
