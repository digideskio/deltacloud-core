module Deltacloud
  module Database

    class Provider
      include DataMapper::Resource

      property :id, Serial
      property :driver, String, :required => true
      property :url, Text

      has n, :entities
      has n, :machine_templates
    end

  end
end