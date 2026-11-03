//! Experimental external-vantage client. No credential values are logged.
#![forbid(unsafe_code)]
use base64::Engine;
use serde::Deserialize;
use std::{fs::File, io::Read, net::{Ipv4Addr, SocketAddr}, os::unix::fs::MetadataExt, path::Path, time::{Duration, SystemTime, UNIX_EPOCH}};
use vp_product_compiler::server_v2::ServerCompilerV2;
use vp_product_core_adapter::managed::probe_client_v2::{https_status_with_trust, HttpsTargetTrust};
use vp_product_domain::{ProductConfig, SecretBytes};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
struct ClientFile {
    schema_version:u16, ca_pem:String, tls_server_name:String, certificate_expires_at_unix:i64,
    permitted_targets:Vec<SocketAddr>, trojan_port:u16, trojan_password:String,
    vless_port:u16, vless_uuid:String, websocket_path:String, websocket_alpn:String,
    shadowsocks_port:u16, shadowsocks_method:String, shadowsocks_password:String,
    vmess_port:Option<u16>, vmess_uuid:Option<String>,
}
impl Drop for ClientFile { fn drop(&mut self) { self.trojan_password.zeroize();self.vless_uuid.zeroize();self.shadowsocks_password.zeroize();if let Some(uuid)=&mut self.vmess_uuid { uuid.zeroize(); } } }
fn read_private(path:&Path)->Result<Zeroizing<Vec<u8>>, &'static str> {
    if !path.is_absolute() { return Err("PRIVATE_FILE_REQUIRED"); }
    let fd=rustix::fs::open(path,rustix::fs::OFlags::RDONLY|rustix::fs::OFlags::NOFOLLOW|rustix::fs::OFlags::NONBLOCK|rustix::fs::OFlags::CLOEXEC,rustix::fs::Mode::empty()).map_err(|_|"PRIVATE_FILE_REQUIRED")?;
    let file=File::from(fd);let m=file.metadata().map_err(|_|"PRIVATE_FILE_REQUIRED")?;
    if !m.is_file() || m.uid()!=rustix::process::geteuid().as_raw() || m.mode()&0o077!=0 || m.len()==0 || m.len()>65536 {return Err("PRIVATE_FILE_REQUIRED");}
    let mut b=Zeroizing::new(Vec::new());file.take(65537).read_to_end(&mut b).map_err(|_|"PRIVATE_FILE_REQUIRED")?;
    if b.len() as u64!=m.len(){return Err("PRIVATE_FILE_REQUIRED");}Ok(b)
}
fn ca_der(pem:&str)->Result<Vec<u8>, &'static str>{
    let text=pem.strip_prefix("-----BEGIN CERTIFICATE-----\n").and_then(|v|v.strip_suffix("-----END CERTIFICATE-----\n")).ok_or("INVALID_CLIENT_FILE")?;
    let mut encoded=String::new();for line in text.lines(){if line.len()>76{return Err("INVALID_CLIENT_FILE");}encoded.push_str(line);}
    let der=base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_|"INVALID_CLIENT_FILE")?;
    if der.is_empty()||der.len()>65536{return Err("INVALID_CLIENT_FILE");}Ok(der)
}
fn validate(f:&ClientFile)->Result<(), &'static str>{
    let now=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"INVALID_CLOCK")?.as_secs();
    if f.schema_version!=1 || f.tls_server_name!="vp-lab.invalid" || f.certificate_expires_at_unix<=now as i64 || f.websocket_path!="/vp" || f.websocket_alpn!="http/1.1" || f.shadowsocks_method!="aes-128-gcm" || [f.trojan_port,f.vless_port,f.shadowsocks_port].contains(&0) || !f.permitted_targets.contains(&"1.1.1.1:443".parse().unwrap()) {return Err("INVALID_CLIENT_FILE");}
    if f.vmess_port.is_some() != f.vmess_uuid.is_some() || f.vmess_port == Some(0) || f.vmess_port.is_some_and(|p| [f.trojan_port,f.vless_port,f.shadowsocks_port].contains(&p)) { return Err("INVALID_CLIENT_FILE"); }
    ca_der(&f.ca_pem)?;Ok(())
}
fn probe(f:&ClientFile,server:Ipv4Addr)->Result<bool, &'static str>{
    let release=vp_product_core_adapter::inspect_build().map_err(|_|"IDENTITY_UNAVAILABLE")?.build.release;
    let target:SocketAddr="1.1.1.1:443".parse().map_err(|_|"INTERNAL")?;
    let compiler=ServerCompilerV2::for_public_experiment(release.clone(),vec![target]).map_err(|_|"INVALID_CONFIG")?;
    let root=ca_der(&f.ca_pem)?;let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|"RUNTIME_UNAVAILABLE")?;
    let mut all=true;
    let mut protocols = vec!["trojan", "vless", "shadowsocks"];
    if f.vmess_port.is_some() { protocols.push("vmess"); }
    for (index,name) in protocols.iter().enumerate(){
        let (port,protocol,transport,security,secret)=match index {
            0=>(f.trojan_port,serde_json::json!({"kind":"trojan"}),serde_json::json!({"kind":"tcp"}),serde_json::json!({"kind":"tls","certificateRef":"probe-certificate","privateKeyRef":"secret:probe-key","alpn":[]}),&f.trojan_password),
            1=>(f.vless_port,serde_json::json!({"kind":"vless","flow":null}),serde_json::json!({"kind":"ws","path":"/vp","host":null,"earlyData":null}),serde_json::json!({"kind":"tls","certificateRef":"probe-certificate","privateKeyRef":"secret:probe-key","alpn":["http/1.1"]}),&f.vless_uuid),
            2=>(f.shadowsocks_port,serde_json::json!({"kind":"shadowsocks","method":"aes-128-gcm"}),serde_json::json!({"kind":"tcp"}),serde_json::json!({"kind":"none"}),&f.shadowsocks_password),
            _=>(f.vmess_port.ok_or("INVALID_CLIENT_FILE")?,serde_json::json!({"kind":"vmess","cipher":"auto","alterId":0}),serde_json::json!({"kind":"ws","path":"/vp","host":null,"earlyData":null}),serde_json::json!({"kind":"tls","certificateRef":"probe-certificate","privateKeyRef":"secret:probe-key","alpn":["http/1.1"]}),f.vmess_uuid.as_ref().ok_or("INVALID_CLIENT_FILE")?),
        };
        let source:ProductConfig=serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{"schemaVersion":1,"id":"probe-listener","name":"probe","enabled":true,"bind":{"address":server,"port":port},"protocol":{"kind":"proxy","protocol":protocol,"users":[{"id":"probe-user","credentialRef":"secret:probe-credential","enabled":true}]},"transport":transport,"security":security,"requirements":[]}]})).map_err(|_|"INVALID_CONFIG")?;
        let compiled=compiler.compile(&source,&release).map_err(|_|"INVALID_CONFIG")?;
        let credential=SecretBytes::new(secret.as_bytes().to_vec());
        let result=rt.block_on(https_status_with_trust(&compiled.listeners[0],&source.listeners[0],target,&credential,std::slice::from_ref(&root),&f.tls_server_name,&HttpsTargetTrust::PublicWebPki,"one.one.one.one","/cdn-cgi/trace",200,Duration::from_secs(10)));
        let passed=matches!(result,Ok(true));all &= passed;
        println!("{{\"protocol\":\"{name}\",\"result\":\"{}\"}}",if passed {"passed"}else{"not_verified"});
    }
    Ok(all)
}
fn main(){
    if std::env::args().skip(1).collect::<Vec<_>>()==["--check-build"] {
        let release=match vp_product_core_adapter::inspect_build(){Ok(v)=>v.build.release,Err(_)=>{eprintln!("VP_CLIENT_REFUSED: IDENTITY_UNAVAILABLE");std::process::exit(1)}};
        let result=serde_json::json!({"architecture":std::env::consts::ARCH,"testFixture":vp_product_core_adapter::local_probe_test_enabled(),"releaseIdentity":release,"networkAccess":false,"writesState":false});
        println!("{result}");return;
    }
    let mut args=std::env::args().skip(1);let mut file=None;let mut ip=None;let mut credential=false;let mut cloudflare=false;
    while let Some(arg)=args.next(){match arg.as_str(){
        "--help"=>{println!("Experimental external client: --credentials-file ABSOLUTE_0600_FILE --server-ip IPV4 --confirm-credential-use --confirm-cloudflare-probe. The server receives test credentials; Cloudflare sees the server's source IP. No credential value is printed.");return;},
        "--credentials-file" if file.is_none()=>file=args.next(),"--server-ip" if ip.is_none()=>ip=args.next(),
        "--confirm-credential-use" if !credential=>credential=true,"--confirm-cloudflare-probe" if !cloudflare=>cloudflare=true,_=>{eprintln!("VP_CLIENT_REFUSED: INVALID_ARGUMENT");std::process::exit(1);}}}
    let result=(||->Result<bool,&'static str>{if !credential||!cloudflare{return Err("CONFIRMATION_REQUIRED");}let path=file.ok_or("MISSING_ARGUMENT")?;let server:Ipv4Addr=ip.ok_or("MISSING_ARGUMENT")?.parse().map_err(|_|"INVALID_SERVER")?;if server.is_loopback()||server.is_unspecified()||server.is_multicast(){return Err("INVALID_SERVER");}let bytes=read_private(Path::new(&path))?;let data:ClientFile=serde_json::from_slice(&bytes).map_err(|_|"INVALID_CLIENT_FILE")?;validate(&data)?;probe(&data,server)})();
    match result {Ok(true)=>{},Ok(false)=>std::process::exit(1),Err(e)=>{eprintln!("VP_CLIENT_REFUSED: {e}");std::process::exit(1)}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture()->ClientFile {
        let cert=rcgen::generate_simple_self_signed(vec!["vp-lab.invalid".into()]).unwrap();
        let raw=base64::engine::general_purpose::STANDARD.encode(cert.cert.der());
        let encoded=raw.as_bytes().chunks(64).map(|c|std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
        ClientFile{schema_version:1,ca_pem:format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n"),tls_server_name:"vp-lab.invalid".into(),certificate_expires_at_unix:4102444800,permitted_targets:vec!["1.1.1.1:443".parse().unwrap()],trojan_port:21001,trojan_password:"local-test-password".into(),vless_port:21002,vless_uuid:"00000000-0000-4000-8000-000000000001".into(),websocket_path:"/vp".into(),websocket_alpn:"http/1.1".into(),shadowsocks_port:21003,shadowsocks_method:"aes-128-gcm".into(),shadowsocks_password:"local-test-password".into(),vmess_port:None,vmess_uuid:None}
    }
    #[test] fn client_file_requires_explicit_target_and_unexpired_certificate(){
        let mut f=fixture();assert!(validate(&f).is_ok());f.permitted_targets.clear();assert!(validate(&f).is_err());
        f.permitted_targets.push("1.1.1.1:443".parse().unwrap());f.certificate_expires_at_unix=1;assert!(validate(&f).is_err());
    }
    #[test] fn three_protocol_configs_reach_an_unreachable_documentation_address(){
        // Reserved test address; no real credential or third-party endpoint is contacted.
        let result=probe(&fixture(),"192.0.2.1".parse().unwrap());
        assert!(matches!(result,Ok(false)),"all three configurations must compile before failed local connection attempts");
    }
    #[test] fn vmess_fields_must_be_paired_and_port_distinct(){
        let mut f=fixture(); f.vmess_port=Some(21004); assert!(validate(&f).is_err());
        f.vmess_uuid=Some("00000000-0000-4000-8000-000000000002".into()); assert!(validate(&f).is_ok());
        f.vmess_port=Some(21001); assert!(validate(&f).is_err());
    }
    #[test] fn four_protocol_configs_reach_unreachable_documentation_address(){
        let mut f=fixture(); f.vmess_port=Some(21004); f.vmess_uuid=Some("00000000-0000-4000-8000-000000000002".into());
        assert!(matches!(probe(&f,"192.0.2.1".parse().unwrap()),Ok(false)));
    }
    #[test] fn malformed_ca_and_changed_transport_are_refused(){
        let mut f=fixture();f.ca_pem="bad".into();assert!(validate(&f).is_err());let mut f=fixture();f.websocket_path="/other".into();assert!(validate(&f).is_err());
    }
    #[test] fn credential_file_requires_private_permissions_and_no_symlink(){
        let tmp=tempfile::tempdir().unwrap();let p=tmp.path().join("client.json");std::fs::write(&p,b"{}").unwrap();std::fs::set_permissions(&p,std::fs::Permissions::from_mode(0o600)).unwrap();assert!(read_private(&p).is_ok());
        std::fs::set_permissions(&p,std::fs::Permissions::from_mode(0o644)).unwrap();assert!(read_private(&p).is_err());
        std::fs::set_permissions(&p,std::fs::Permissions::from_mode(0o600)).unwrap();let link=tmp.path().join("link");std::os::unix::fs::symlink(&p,&link).unwrap();assert!(read_private(&link).is_err());
    }
}
