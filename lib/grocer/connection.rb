require 'grocer'
require 'grocer/no_gateway_error'
require 'grocer/no_port_error'
require 'grocer/ssl_connection'

module Grocer
  class Connection
    attr_reader :certificate, :certificate_data, :passphrase, :gateway, :port, :retries

    def initialize(options = {})
      @certificate = options.fetch(:certificate) { nil }
      @certificate_data = options.fetch(:certificate_data) { nil }
      @passphrase = options.fetch(:passphrase) { nil }
      @gateway = options.fetch(:gateway) { fail NoGatewayError }
      @port = options.fetch(:port) { fail NoPortError }
      @retries = options.fetch(:retries) { 3 }
    end

    def read(size = nil, buf = nil)
      with_connection do
        ssl.read(size, buf)
      end
    end

    def write(content)
      with_connection do
        ssl.write(content)
      end
    end

    def connect
      ssl.connect unless ssl.connected?
    end

    private

    def ssl
      @ssl_connection ||= build_connection
    end

    def build_connection
      Grocer::SSLConnection.new(certificate: certificate,
                                certificate_data: certificate_data,
                                passphrase: passphrase,
                                gateway: gateway,
                                port: port)
    end

    def destroy_connection
      return unless @ssl_connection

      @ssl_connection.disconnect rescue nil
      @ssl_connection = nil
    end

    def with_connection
      attempts = 1
      begin
        connect
        yield
      rescue StandardError, Errno::EPIPE
        raise unless attempts < retries

        destroy_connection
        attempts += 1
        retry
      end
    end
  end
end
