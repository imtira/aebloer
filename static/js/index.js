var sidenav, formSelectElems;
var xhr = new XMLHttpRequest();

$(document).ready(() => {
  $('.sidenav').sidenav();
  $('select').formSelect();
  $('#hash-algorithm').change(() => {
    hash($('#hash-textarea').val());
  });
  $('.charset-tooltip, .timeout-tooltip, .port-range-tooltip').darkTooltip({
    animation: 'none',
    gravity: 'south',
    theme: 'dark',
    size: 'medium'
  });
  $('#charset-selector, #generate-length').on('change keyup', () => {
    if ($('#charset-selector input[type=\'radio\']:checked').val() === 'default') {
      $('#custom-charset').prop('readonly', true);
    } else {
      $('#custom-charset').prop('readonly', false);
    }
    generate_string();
  });
  $('#port-range').on('change keyup', () => {
    if ($('#port-range input[type=\'radio\']:checked').val() === 'default') {
      $('#custom-port-low, #custom-port-high').prop('readonly', true);
    } else {
      $('#custom-port-low, #custom-port-high').prop('readonly', false);
    }
  });
  $('#timeout-selector').on('change keyup', () => {
    if ($('#timeout-selector input[type=\'radio\']:checked').val() === 'default') {
      $('#custom-timeout').prop('readonly', true);
    } else {
      $('#custom-timeout').prop('readonly', false);
    }
  });
  $('#exif-image-upload').on('change', () => {
    if ($('#viewstrip-exif input[type=\'radio\']:checked').val() === 'view') {
      view_exif();
    } else {
      strip_exif();
    }
  });
});

function scroll_to(element) {
  document.querySelector(element).scrollIntoView({
    behavior: 'smooth'
  });
}

function hash(toHash) {
  var hashType = $('select').val();
  var output = $('#hash-output');
  xhr.open('POST', '/hash', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      var response = JSON.parse(xhr.responseText);
      if (response.error) {
        output.val(response.error);
      } else {
        output.val(response.result);
      }
      if (!$('#hash-output-label').hasClass('active')) {
        $('#hash-output-label').addClass('active');
      }
    }
  };
  xhr.send('string=' + encodeURIComponent(toHash) + '&hash=' + encodeURIComponent(hashType));
}

function generate_string() {
  var output = $('#generate-output');
  xhr.open('POST', '/generate', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      var response = JSON.parse(xhr.responseText);
      if (response.error) {
        output.val(response.error);
      } else {
        output.val(response.result);
      }
    }
  };
  var charset;
  if ($('#custom-charset').prop('readonly') === false
    && $('#custom-charset').val().length >= 1) {
    charset = $('#custom-charset').val();
  } else {
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()" +
      "_+~{}|:\"<>?';/.,\\][]`";
  }
  length = $('#generate-length').val();
  if (length <= 0) {
    length = 1;
  }
  xhr.send('length=' + encodeURIComponent(length) + '&charset=' + encodeURIComponent(charset));
}

function scan_ports() {
  var output = $('#open-ports-output');
  xhr.open('POST', '/scan', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      var response = JSON.parse(xhr.responseText);
      if (response.error) {
        output.val(response.error);
      } else {
        output.val(response.result);
        $('.preloader-wrapper').delay(200).fadeOut();
      }
    }
  };
  var address = $('#port-scan-address').val();
  var timeout;
  var port_low, port_high;
  if ($('#custom-port-low').prop('readonly') === false
    && (Number($('#custom-port-high').val()) >= Number($('#custom-port-low').val()))
    && ($('#custom-port-low').val() + $('#custom-port-high').val() !== "00")
    && ($('#custom-port-low').val() + $('#custom-port-high').val() !== "")) {
    port_low = $('#custom-port-low').val();
    port_high = $('#custom-port-high').val();
  } else {
    port_low = 1;
    port_high = 65565;
  }
  if ($('#custom-timeout').prop('readonly') === false) {
    timeout = Number($('#custom-timeout').val()) ? $('#custom-timeout').val() : 500;
  } else {
    timeout = "500";
  }
  $('.preloader-wrapper').delay(200).fadeIn();
  xhr.send('address=' + encodeURIComponent(address) + '&portLow=' +
    encodeURIComponent(port_low) + '&portHigh=' + encodeURIComponent(port_high) + '&timeout=' + encodeURIComponent(timeout));
}

function timeresponses() {
  var address = $('#timeresponses-address').val();
  var output = $('#timeresponses-output');
  xhr.open('POST', '/timeresponses', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      var response = JSON.parse(xhr.responseText);
      if (response.error) {
        output.val(response.error);
      } else {
        output.val(response.result.trim());
        M.textareaAutoResize(output);
      }
    }
  }
  xhr.send('address=' + encodeURIComponent(address));
}

function resolve() {
  var address = $('#resolve-address').val();
  var output = $('#resolve-output');
  xhr.open('POST', '/resolve', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      var response = JSON.parse(xhr.responseText);
      if (response.error) {
        output.val(response.error);
      } else {
        output.val(response.result);
      }
    }
  }
  xhr.send('address=' + encodeURIComponent(address));
}

function view_exif() {
  var files_base64 = get_images();
  xhr.open('POST', '/exif', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.onreadystatechange = () => {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      console.log(xhr.responseText);
      var response = JSON.parse(xhr.responseText);
      if (response.error) {
        output.val(response.error);
      } else {

      }
    }
  }
  JSON.stringify(files_base64)
  xhr.send('mode=' + encodeURIComponent($('#viewstrip-exif input[type=\'radio\']:checked').val()) + '&files=' + encodeURIComponent(JSON.stringify(files_base64)));
}

function get_images() {
  var files = $('#exif-image-upload').prop('files');
  var files_base64 = {};
  for (var i = 0, file; file = files[i]; i++) {
    var reader = new FileReader();
    reader.onload = e => {
      files_base64[i] = e.target.result;
    }
    reader.readAsDataURL(file);
  }
  return files_base64;
}