require "openssl"
require "socket"
require "tmpdir"

class TLSTestServer
  attr_reader :port, :ca_file

  def initialize
    @directory = Dir.mktmpdir("trilogy-tls-test-")
    @ca_file = File.join(@directory, "ca.pem")
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=trilogy-test")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    extensions = OpenSSL::X509::ExtensionFactory.new
    extensions.subject_certificate = extensions.issuer_certificate = cert
    cert.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(extensions.create_extension("subjectAltName", "DNS:localhost"))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    File.write(@ca_file, File.read(OpenSSL::X509::DEFAULT_CERT_FILE) + cert.to_pem)

    context = OpenSSL::SSL::SSLContext.new
    context.cert = cert
    context.key = key
    context.min_version = context.max_version = OpenSSL::SSL::TLS1_2_VERSION

    listener = TCPServer.new("127.0.0.1", 0)
    @port = listener.addr[1]
    @pid = fork do
      Thread.abort_on_exception = true
      loop do
        socket = listener.accept
        socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        Thread.new(socket) { |connection| serve(connection, context) }
      end
    end
    listener.close
  end

  def options
    {
      host: "localhost",
      port: port,
      username: "test",
      password: "",
      ssl_mode: Trilogy::SSL_VERIFY_IDENTITY,
      ssl_ca: ca_file,
      tls_min_version: Trilogy::TLS_VERSION_12,
      tls_max_version: Trilogy::TLS_VERSION_12,
      connect_timeout: 5,
      read_timeout: 5,
      write_timeout: 5,
    }
  end

  def close
    if @pid
      Process.kill("TERM", @pid)
      Process.wait(@pid)
      @pid = nil
    end
    if @directory
      Dir.each_child(@directory) { |name| File.unlink(File.join(@directory, name)) }
      Dir.rmdir(@directory)
      @directory = nil
    end
  end

  private

  def packet(socket, payload, sequence)
    socket.write([payload.bytesize].pack("V").byteslice(0, 3) + [sequence].pack("C") + payload)
  end

  def receive_packet(socket)
    header = socket.read(4)
    return unless header
    raise IOError, "truncated MySQL header" unless header.bytesize == 4

    length = header.unpack1("V") & 0xffffff
    payload = socket.read(length)
    raise IOError, "truncated MySQL payload" unless payload && payload.bytesize == length

    [header.getbyte(3), payload]
  end

  def serve(socket, context)
    capabilities = 0x00088a01
    greeting = "\x0a8.0.0-trilogy-test\0" + [1].pack("V") + "12345678\0" +
      [capabilities & 0xffff, 45, 2, capabilities >> 16, 21].pack("vCvvC") +
      ("\0" * 10) + "abcdefghijkl\0mysql_native_password\0"
    packet(socket, greeting, 0)
    request = receive_packet(socket)
    raise IOError, "expected MySQL SSLRequest" unless request && request[0] == 1 && request[1].bytesize == 32

    tls = OpenSSL::SSL::SSLSocket.new(socket, context)
    tls.sync_close = true
    tls.accept
    auth = receive_packet(tls)
    raise IOError, "expected MySQL authentication" unless auth && auth[0] == 2

    packet(tls, "\0\0\0\x02\0\0\0", 3)
    while message = receive_packet(tls)
      case message[1].getbyte(0)
      when 1
        break
      when 14
        packet(tls, "\0\0\0\x02\0\0\0", 1)
      else
        raise IOError, "unsupported test MySQL command"
      end
    end
  rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET, Errno::EPIPE => error
    warn "TLS test peer closed: #{error.class}: #{error.message}"
  ensure
    tls&.close
    socket.close unless socket.closed?
  end
end
