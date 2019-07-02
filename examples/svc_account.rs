use tame_oauth::gcp::prelude::*;

fn main() {
    let mut args = std::env::args().skip(1);

    let key_path = args
        .next()
        .expect("expected path to a service account json file");
    let scopes: Vec<_> = args.collect();

    use bytes::BufMut;

    let service_key = std::fs::read_to_string(key_path).expect("failed to read json key");

    let acct_info = ServiceAccountInfo::deserialize(service_key).unwrap();
    let acct_access = ServiceAccountAccess::new(acct_info).unwrap();

    let token = match acct_access.get_token(&scopes).unwrap() {
        TokenOrRequest::Request {
            request,
            scope_hash,
            ..
        } => {
            let client = reqwest::Client::new();

            let (parts, body) = request.into_parts();
            let uri = parts.uri.to_string();

            let builder = match parts.method {
                http::Method::GET => client.get(&uri),
                http::Method::POST => client.post(&uri),
                http::Method::DELETE => client.delete(&uri),
                http::Method::PUT => client.put(&uri),
                method => unimplemented!("{} not implemented", method),
            };

            let request = builder.headers(parts.headers).body(body).build().unwrap();

            let mut response = client.execute(request).unwrap();

            let mut writer =
                bytes::BytesMut::with_capacity(response.content_length().unwrap_or(1024) as usize)
                    .writer();
            response.copy_to(&mut writer).unwrap();
            let buffer = writer.into_inner();

            let mut builder = http::Response::builder();

            builder
                .status(response.status())
                .version(response.version());

            let headers = builder.headers_mut().unwrap();

            headers.extend(
                response
                    .headers()
                    .into_iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            );

            let response = builder.body(buffer.freeze()).unwrap();

            acct_access
                .parse_token_response(scope_hash, response)
                .unwrap()
        }
        _ => unreachable!(),
    };

    match acct_access.get_token(&scopes).unwrap() {
        TokenOrRequest::Token(tk) => {
            assert_eq!(tk, token);
            println!(
                "cool, you were able to retrieve a token for the {:?} scope{}!",
                scopes,
                if scopes.len() == 1 { "" } else { "s" }
            );
        }
        _ => unreachable!(),
    }
}
