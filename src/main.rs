use std::env;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{BufReader, Read, Write, stdout};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use rustls::pki_types::CertificateDer;

use rustls::*;
// use rustls_pemfile::*;
// use webpki_roots::*;

fn client() -> Result<(), Box<dyn StdError>> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?; // Use ? for error handling

    let mut sock = TcpStream::connect("www.rust-lang.org:443")?; // Use ? for error handling

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )?;

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )?;

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext)?;
    stdout().write_all(&plaintext)?;

    Ok(())
}

fn server() -> Result<(), Box<dyn StdError>> {
    let mut args = env::args();
    args.next();
    let cert_file = args.next().expect("missing certificate file argument");
    let private_key_file = args.next().expect("missing private key file argument");

    let mut certs = Vec::new();
    let mut error_occured = false;
    for cert_result in rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_file)?)) {
      match cert_result {
        Ok(cert) => certs.push(cert),
        Err(err) => {
          eprintln!("Error reading certificate: {}", err);
          error_occured = true;
        }
      }
    }
    
    if error_occured {
      // Handle the error appropriately, maybe exit the program
      return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Error reading certificates")));
    }    
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(private_key_file)?))?; 

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key.unwrap())?; 

    let listener = TcpListener::bind(format!("[::]:{}", 4443))?;
    let (mut stream, _) = listener.accept()?;

    let mut conn = rustls::ServerConnection::new(Arc::new(config))?; 
    conn.complete_io(&mut stream)?;

    conn.writer().write_all(b"Hello from the server")?;
    conn.complete_io(&mut stream)?;

    let mut buf = [0; 64];
    let len = conn.reader().read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);

    Ok(())
}

fn main() {
    thread::spawn(|| server().unwrap());
    client().unwrap(); 
}
