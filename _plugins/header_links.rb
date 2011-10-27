require "nokogiri"

module Jekyll
  module HeaderLinks
    def header_links(content)
      doc = Nokogiri::HTML(content)
      doc.css("h3").each do |h|
        temp = h.inner_html
        anchor = "#{temp.gsub(/[^a-zA-Z0-9]/, "")}"
        h.inner_html = '<a href="#' + anchor + '" id="' + anchor + '" class="blog-header">' + temp + '</a>'
      end
      doc.inner_html
    end
  end
end

Liquid::Template.register_filter(Jekyll::HeaderLinks)
