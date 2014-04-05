$(document).ready(function(e) {

  var sdp = $('#sdp').val()
  var req = { act: "sdp_offer", offer: sdp };

  $.ajax({
    url:"https://localhost:7777/api/v1/get",
    type:'POST',
    processData:false,
    data: JSON.stringify(req),
    success:function(e) {
      console.log("suc!");
    }
  });
});
