class Trilogy
  class SSLContext
    OPTION_KEYS = %i[
      ssl_mode ssl_ca ssl_capath ssl_cert ssl_cipher ssl_crl ssl_crlpath ssl_key
      tls_ciphersuites tls_min_version tls_max_version
    ].freeze

    attr_reader :options

    def initialize(options = {})
      unknown = options.keys - OPTION_KEYS
      raise ArgumentError, "unknown SSLContext options: #{unknown.join(', ')}" unless unknown.empty?

      @options = { ssl_mode: Trilogy::SSL_VERIFY_IDENTITY }.merge(options).transform_values do |value|
        value.is_a?(String) ? value.dup.freeze : value
      end.freeze
      _initialize(@options)
      freeze
    end

    def initialize_copy(_other)
      raise TypeError, "SSLContext cannot be copied"
    end
  end
end
