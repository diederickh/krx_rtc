$(document).ready(function(e) {

  var sdp = $('#sdp').val()
  var req = { act: "sdp_offer", offer: sdp };
  
  //$.post("https://localhost:7777/api/v1/get", req);

  $.ajax({
    url:"https://localhost:7777/api/v1/get",
    type:'POST',
    processData:false,
    data: JSON.stringify(req),
    success:function(e) {
      console.log("suc!");
    }
    ,fail: function(e) {
      console.log("FAIL.\n");
    }
  });

  /*
  function reqListener () {
    console.log(this.responseText);
  }

  var oReq = new XMLHttpRequest();
  oReq.onload = reqListener;
  oReq.open("get", "https://localhost:7777/api/v1/get", true);
  oReq.send();
  */
});
