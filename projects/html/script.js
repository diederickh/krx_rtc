/*

 WebRTC
 ------

 Very basic and limited webrtc code that is used to debug/test
 krx_rtc. Open this file in Firefox only for now. 

*/
navigator.getUserMedia = navigator.getUserMedia 
                         || navigator.webkitGetUserMedia
                         || navigator.mozGetUserMedia;

var vid = null;
var pc = null;
var sdp_input = null;

function krx_init() {
  
  vid = $('#input_video')[0];
  sdp_input = $('#video_input_sdp');

  // peer connections
  pc = new mozRTCPeerConnection();
  pc.onicecandidate = function(evt) {
    console.log("onicecandidate");
    console.log(evt);
    console.log(evt.candidate);
  };

  // user media callbacks
  var krx_gum_success = function(stream) {

    vid.mozSrcObject = stream;
    vid.play();
  
    pc.addStream(stream);

    // load the SDP 
    pc.createOffer(
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
  $("#init_gum").click(function() {
    navigator.getUserMedia({video:true}, krx_gum_success, krx_gum_error);
  });
}

$(document).ready(function() {
  krx_init();
});
