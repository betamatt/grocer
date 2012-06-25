require 'spec_helper'
require 'grocer/ssl_connection'

describe Grocer::SSLConnection do
  def stub_sockets
    TCPSocket.stubs(:new).returns(mock_socket)
    OpenSSL::SSL::SSLSocket.stubs(:new).returns(mock_ssl)
  end

  def stub_certificate
    example_data = File.read(File.dirname(__FILE__) + '/../fixtures/example.pem')
    File.stubs(:read).with(connection_options[:certificate]).returns(example_data)
  end

  let(:mock_socket) { stub_everything }
  let(:mock_ssl)    { stub_everything }

  let(:connection_options) {
    {
      certificate: '/path/to/cert.pem',
      passphrase:  'abc123',
      gateway:     'gateway.push.highgroove.com',
      port:         1234
    }
  }

  subject { described_class.new(connection_options) }

  describe 'configuration' do
    it 'is initialized with a certificate' do
      subject.certificate.should == connection_options[:certificate]
    end

    it 'is initialized with a passphrase' do
      subject.passphrase.should == connection_options[:passphrase]
    end

    it 'is initialized with a gateway' do
      subject.gateway.should == connection_options[:gateway]
    end

    it 'is initialized with a port' do
      subject.port.should == connection_options[:port]
    end

    context 'with preloaded certificate' do
      let(:connection_options) { { certificate_data: 'contents of a cert',
                                   gateway: 'push.example.com',
                                    port: 443 } }

      it 'can be initialized with certificate data' do
        subject.certificate_data.should == connection_options[:certificate_data]
      end
    end
  end

  describe 'connecting' do
    before do
      stub_sockets
      stub_certificate
    end

    it 'sets up an socket connection' do
      subject.connect
      TCPSocket.should have_received(:new).with(connection_options[:gateway],
                                                connection_options[:port])
    end

    it 'sets up an SSL connection' do
      subject.connect
      OpenSSL::SSL::SSLSocket.should have_received(:new).with(mock_socket, anything)
    end
  end

  describe "connecting with preloaded certificate" do
    before do
      stub_sockets
    end

    let(:connection_options) {
      {
        certificate_data: File.read(File.dirname(__FILE__) + '/../fixtures/example.pem'),
        passphrase:  'abc123',
        gateway:     'gateway.push.highgroove.com',
        port:         1234
      }
    }

    it "sets up an SSL connection using certificate data" do
      subject.connect
      OpenSSL::SSL::SSLSocket.should have_received(:new).with(mock_socket, anything)
    end
  end

  describe 'connecting with pkcs12 cert' do
    before do
      stub_sockets
    end

    let(:connection_options) { { 
      certificate: OpenSSL::PKCS12.new(File.read(File.dirname(__FILE__) + '/../fixtures/example.pk12')),
      gateway:     'gateway.push.highgroove.com',
      port:         1234
    } }

    it "sets up an SSL connection using certificate key" do
      subject.connect
      OpenSSL::SSL::SSLSocket.should have_received(:new).with(mock_socket, anything)
    end
  end


  describe 'writing data' do
    before do
      stub_sockets
      stub_certificate
    end

    it 'writes data to the SSL connection' do
      subject.connect
      subject.write('abc123')

      mock_ssl.should have_received(:write).with('abc123')
    end
  end

  describe 'reading data' do
    before do
      stub_sockets
      stub_certificate
    end

    it 'reads data from the SSL connection' do
      subject.connect
      subject.read(42)

      mock_ssl.should have_received(:read).with(42)
    end
  end
end
