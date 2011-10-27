require "sass"

module Jekyll
  class SassConverter < Converter
    safe true

    def matches(ext)
      ext =~ /scss/i
    end

    def output_ext(ext)
      ".css"
    end

    def convert(content)
      Sass.compile(content)
    end
  end
end
