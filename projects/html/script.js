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
  sdp_output = document.getElementById('video_output_sdp');
  sdp_input = document.getElementById('video_input_sdp');
  sdp_output.value = '';
  sdp_input.value = '';


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
    console.log(evt);
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
        console.log("offer", desc.sdp);

        // send the password + change the UDP port of the first candidate
        var changed_sdp = "";
        var candidate_changed = false;
        var lines = desc.sdp.split("\n");
        for(var i = 0; i < lines.length; ++i) {
          
          // password
          var line = lines[i].split("a=ice-pwd:");
          if(line.length > 1 && line[1].length > 0) {
            $.get("http://localhost:3333/?passwd=" +line[1], function(r) {
              console.log("ice-pwd ok.\n");
            });

            changed_sdp += lines[i];
            continue;
          }

          // change first candidate
          line = lines[i].split("a=candidate:0");
          if(line.length > 1 && line[1].length > 0 && candidate_changed == false) {
            cparts = line[1].split(' ');
            cparts[5] = "2233";
            changed_sdp += "a=candidate:0" +cparts.join(" ");
            candidate_changed = true;
            continue;
          }

          changed_sdp += lines[i];
        }

        sdp_input.value = changed_sdp;
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
    navigator.getUserMedia({video:true, audio:false}, krx_gum_success, krx_gum_error);
  });

  $('#start_streaming').click(function(){

    // get sdp from textarea
    var input_sdp_val = document.getElementById("video_input_sdp").value;
    if(input_sdp_val.length == 0) {
      console.log("No sdp text found.");
      return;
    }

    console.log("sdp_input", input_sdp_val);

    sdp_output.value = input_sdp_val;

    // set the offer SDPs
    var isdp = new window.RTCSessionDescription({type:"offer", sdp:input_sdp_val});
    pc_receiver.setRemoteDescription(isdp);
    pc_sender.setLocalDescription(isdp);

    // set the answer SDPs
    pc_receiver.createAnswer(
      function(desc) {
        //console.log("createdAnswer.");
        //console.log(desc);
        var remote_changed_sdp = new window.RTCSessionDescription({type:"answer", sdp:input_sdp_val});
        //console.log("using");
        console.log(input_sdp_val);
        
        pc_sender.setRemoteDescription(remote_changed_sdp);
        //pc_sender.setRemoteDescription(desc);
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
