function find_header_by_position(position) {
  var i;
  for (i = $.headers.length - 1; i > 0; --i) {
    if (position > $.headers[i][0])
      return $.headers[i];
  }
}

function display_header() {
  if ($.current_header === undefined) return;
  var temp = $($("#" + $.current_header[1]).parent().html()).removeAttr("id");
  $("#current-header").html(temp);
}

function adjust_header_size() {
  var max_width = ($(window).width() - $(".blog-post").width()) / 2;
  max_width -= 10;
  $("#current-header").css("width", max_width);
}

$(function() {
  adjust_header_size();

  $.headers = [];
  $.scroll_event = false;
  $(".blog-header").each(function() {
    var temp = [ $(this).position().top, $(this).attr("id") ];
    $.headers.push(temp);
  });
  $.current_header = find_header_by_position($(window).scrollTop());
  display_header();

  $(window).scroll(function() {
    // Stops first scroll event, thus preventing a double fade
    // sequence on page load.
    if (!$.scroll_event) {
      $.scroll_event = true;
      return;
    }

    var header = find_header_by_position($(window).scrollTop());
    if ($.current_header != header) {
      $.current_header = header;
      display_header();
    }
  });
});
