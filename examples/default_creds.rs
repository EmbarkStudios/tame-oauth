use tame_oauth::gcp::*;

// This example shows the basics for creating a token provider for the default
// credentials on the system. If you want to use a service account, set
// `GOOGLE_APPLICATION_CREDENTIALS` to a service account key path, if have
// gcloud installed, you can just run this as is and it will work as long as
// you have done `gcloud auth application-default login` previously, and that
// token hasn't expired
#[tokio::main]
async fn main() {
    let scopes: Vec<_> = std::env::args().skip(1).collect();

    let provider = TokenProviderWrapper::get_default_provider()
        .expect("unable to read default token provider")
        .expect("unable to find default token provider");

    println!("Using {}", provider.kind());

    // Attempt to get a token, since we have never used this accessor
    // before, it's guaranteed that we will need to make an HTTPS
    // request to the token provider to retrieve a token. This
    // will also happen if we want to get a token for a different set
    // of scopes, or if the token has expired.
    match provider.get_token(&scopes).unwrap() {
        TokenOrRequest::Request {
            // This is an http::Request that we can use to build
            // a client request for whichever HTTP client implementation
            // you wish to use
            request,
            scope_hash,
            ..
        } => {
            let client = reqwest::Client::new();

            let (parts, body) = request.into_parts();
            let uri = parts.uri.to_string();

            // This will always be a POST, but for completeness sake...
            let builder = match parts.method {
                http::Method::GET => client.get(&uri),
                http::Method::POST => client.post(&uri),
                http::Method::DELETE => client.delete(&uri),
                http::Method::PUT => client.put(&uri),
                method => unimplemented!("{} not implemented", method),
            };

            // Build the full request from the headers and body that were
            // passed to you, without modifying them.
            let request = builder.headers(parts.headers).body(body).build().unwrap();

            // Send the actual request
            let response = client.execute(request).await.unwrap();

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            let headers = builder.headers_mut().unwrap();

            // Unfortunately http doesn't expose a way to just use
            // an existing HeaderMap, so we have to copy them :(
            headers.extend(
                response
                    .headers()
                    .into_iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            );

            let buffer = response.bytes().await.unwrap();
            let response = builder.body(buffer).unwrap();

            provider
                .parse_token_response(scope_hash, response)
                .expect("invalid token response");

            println!("cool, we were able to receive a token!");
        }
        _ => unreachable!(),
    }
}
