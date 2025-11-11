function init_widget(merchant="-", amount="0", qr_code="", ttl=0) {
  $("#pass-payment").css("display", "block");
  $("#pass-payment-help-text").html('Та QR кодыг уншуулах эсвэл утасны дугаараа оруулан төлбөр тооцоогоо хийнэ үү.');
  $("#pass-payment-qr").css('display', 'block');
  $("#pass-payment-control").css('display', 'block');

  $("#pass-payment-top-info-merchant-name").html(merchant);
  var amount_formatted = amount_format(amount);
  $("#pass-payment-top-info-amount-value").html(amount_formatted);

  countdown = ttl;
  generate_qr(qr_code);
  countdown_number_el.textContent = countdown_format(countdown);

  $('#pass-payment-top-timer svg circle').css('animation', 'none');
  var countdown_circle = document.getElementById('pass-payment-top-timer-circle');
  countdown_circle.classList.remove("animated");
  if (!countdown_circle.classList.contains("animated")) {
    window.setTimeout(function () {
      $('#pass-payment-top-timer svg circle').css('animation-play-state', 'initial');
      $("#pass-payment-top-timer svg circle").css("animation", "countdown " + ttl + "s linear infinite forwards");
      countdown_circle.classList.add("animated");
    }, 600);
  }

  clearInterval(countdownInterval);

  countdownInterval = setInterval(function () {
    if (countdown < 1) {
      countdown_number_el.textContent = "0:00";
      $('#pass-payment-top-timer svg circle').css('animation-play-state', 'paused');

      // stop countdown
      clearInterval(countdownInterval);
      var countdown_circle = document.getElementById('pass-payment-top-timer-circle');
      countdown_circle.classList.remove("animated");

      // stop inquiry
      clearInterval(inquiryInterval);

      // display inquiry result
      $("#pass-payment-help-text").html("Хугацаа дууссан");
      $("#pass-payment-qr").css('display', 'none');
      $("#pass-payment-control").css('display', 'none');
    } else {
      countdown = --countdown;
      countdown_number_el.textContent = countdown_format(countdown);
    }
  }, 1000);

  clearInterval(inquiryInterval);
  is_inquiring = false;

  inquiryInterval = setInterval(function () {
    if (!is_inquiring) {
      is_inquiring = true;
      var order_id = qr_code;

      $.ajax({
        'type': "POST",
        'cache': false,
        'dataType': 'json',
        'data': {
          "order_id": order_id
        },
        'url': "/inquiry",
        'success': function (json) {
          if (json['status'] == 'pending') {
            return;
          } else {
            // stop countdown
            clearInterval(countdownInterval);
            var countdown_circle = document.getElementById('pass-payment-top-timer-circle');
            countdown_circle.classList.remove("animated");

            // stop inquiry
            clearInterval(inquiryInterval);

            // display inquiry result
            $("#pass-payment-help-text").html(json['status_text']);
            $("#pass-payment-qr").css('display', 'none');
            $("#pass-payment-control").css('display', 'none');
          }
        },
        'complete': function (json) {
          is_inquiring = false
        }
      });
    }
  }, 5000)
}

function cancel_order() {
  // stop countdown
  clearInterval(countdownInterval);
  $('#pass-payment-top-timer svg circle').css('animation', 'none');
  var countdown_circle = document.getElementById('pass-payment-top-timer-circle');
  countdown_circle.classList.remove("animated");

  // stop inquiry
  clearInterval(inquiryInterval);

  // display cancelation
  $("#pass-payment-help-text").html('Цуцласан');
  $("#pass-payment-qr").css('display', 'none');
  $("#pass-payment-control").css('display', 'none');
}

function notify_phone() {
  var pos = $("#id_pos").val();
  var order_id = qr.get()['value'];
  var phone = $("#pass-payment-phone-input").val();

  $.ajax({
    'type': "POST",
    'cache': false,
    'dataType': 'json',
    'data': {
      "method": "notify_phone",
      "data": JSON.stringify({ "pos": pos, "order_id": order_id, "phone": phone })
    },
    'url': "{% url 'ecommerce_test_widget' %}",
    'success': function (json) {
      console.log("notify phone success");
      console.dir(json);
    },
    'complete': function (json) {
      is_inquiring = false
      console.log("done inquiring")
    }
  });
}

function amount_format(amount) {
  var formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'MNT',
  });
  return formatter.format(amount);
}

function countdown_format(seconds) {
  minutes = Math.floor(seconds / 60);
  seconds = String(seconds % 60);
  if (seconds < 10) {
    seconds = "0" + seconds
  }
  return minutes + ":" + seconds;
}

function generate_qr(qr_value) {
  qr.set({
    value: qr_value
  });
}

var countdown_number_el = document.getElementById('pass-payment-top-timer-number');
var countdown = 0;
var countdownInterval;
var inquiryInterval;
var qr;
var is_inquiring = false;
$(document).ready(function () {
  qr = new QRious({
    element: document.getElementById('pass-payment-qr-code'),
    size: 125,
    foreground: 'white',
    background: '#242834',
  });

  /*
   * web view-с доорх утгуудыг дамжуулна уу
   * init_widget("<MERCHANT NAME>", "<AMOUNT>", "<ORDER ID>", <ORDER TTL>);
  */
});