require "test_helper"
require_relative "support/tls_server"

class SSLContextTest < Minitest::Test
  def setup
    @server = TLSTestServer.new
    @options = @server.options
    @tls_options = @options.select { |key, _| [:ssl_mode, :ssl_ca, :tls_min_version, :tls_max_version].include?(key) }
    @network_options = @options.reject { |key, _| @tls_options.key?(key) }
  end

  def teardown
    @server.close
  end

  def connect(context, **options)
    client = Trilogy.new(@network_options.merge(options).merge(ssl_context: context))
    assert client.ping
    client
  end

  def test_reuses_loaded_trust_store_without_reopening_ca_file
    context = Trilogy::SSLContext.new(@tls_options)
    connect(context).close
    File.unlink(@server.ca_file)
    GC.start
    GC.compact if GC.respond_to?(:compact)
    connect(context).close
    assert_raises(Trilogy::Error) { Trilogy::SSLContext.new(@tls_options) }
  end

  def test_hostname_validation_is_per_connection
    context = Trilogy::SSLContext.new(@tls_options)
    connect(context).close
    assert_raises(Trilogy::SSLError) { connect(context, host: "127.0.0.1") }
    connect(context).close
  end

  def test_rejects_conflicting_connection_tls_options
    context = Trilogy::SSLContext.new(@tls_options)
    error = assert_raises(ArgumentError) { connect(context, ssl_mode: Trilogy::SSL_REQUIRED_NOVERIFY) }
    assert_includes error.message, "ssl_mode"
  end

  def test_contexts_do_not_share_trust_stores
    other = TLSTestServer.new
    context = Trilogy::SSLContext.new(@tls_options.merge(ssl_ca: other.ca_file))
    assert_raises(Trilogy::SSLError) { connect(context) }
  ensure
    other&.close
  end

  def test_contexts_do_not_share_protocol_settings
    tls12 = Trilogy::SSLContext.new(@tls_options)
    tls13 = Trilogy::SSLContext.new(@tls_options.merge(
      tls_min_version: Trilogy::TLS_VERSION_13,
      tls_max_version: Trilogy::TLS_VERSION_13,
    ))
    connect(tls12).close
    assert_raises(Trilogy::SSLError) { connect(tls13) }
    connect(tls12).close
  end

  def test_legacy_connections_keep_hostname_verification
    client = Trilogy.new(@options)
    assert client.ping
    client.close
    assert_raises(Trilogy::SSLError) { Trilogy.new(@options.merge(host: "127.0.0.1")) }
  end

  def test_reuses_context_across_threads
    context = Trilogy::SSLContext.new(@tls_options)
    workers = Array.new(4) do
      Thread.new do
        3.times do
          client = Trilogy.new(@network_options.merge(ssl_context: context))
          raise "ping failed" unless client.ping
          client.close
        end
      end
    end
    workers.each(&:value)
  end

  def test_freezes_options_without_freezing_caller_strings
    path = @server.ca_file.dup
    context = Trilogy::SSLContext.new(@tls_options.merge(ssl_ca: path))
    path.replace("changed.pem")
    assert_equal @server.ca_file, context.options[:ssl_ca]
    assert context.frozen?
    assert context.options.frozen?
    assert context.options[:ssl_ca].frozen?
    connect(context).close
    assert_raises(TypeError) { context.dup }
  end

  def test_rejects_disabled_tls_and_unknown_context_options
    assert_raises(ArgumentError) { Trilogy::SSLContext.new(ssl_mode: Trilogy::SSL_DISABLED) }
    assert_raises(ArgumentError) { Trilogy::SSLContext.new(ssl_ca_typo: "wrong.pem") }
    assert_raises(TypeError) { Trilogy.new(@network_options.merge(ssl_context: Object.new)) }
    assert_raises(TypeError) { Trilogy.new(@network_options.merge(ssl_context: false)) }
  end
end
