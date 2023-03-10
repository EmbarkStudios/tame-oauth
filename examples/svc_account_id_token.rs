use tame_oauth::gcp::*;

use bytes::Bytes;

// This example shows the basics for creating a GCP service account token
// provider and requesting a token from it. This particular example uses the
// reqwest HTTP client, but the point of this crate is that you can use
// whichever one you like as long as you don't mind doing a little bit of
// boilerplate to convert between from http::Request and to http::Response
#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);

    let key_path = args
        .next()
        .expect("expected path to a service account json file");
    let service_key = std::fs::read_to_string(key_path).expect("failed to read json key");

    // Deserialize the service account info from the json data
    let acct_info = ServiceAccountInfo::deserialize(service_key).unwrap();

    // Create the token provider!
    let sa_provider = ServiceAccountProvider::new(acct_info).unwrap();

    let audience = "my-audience";

    // Attempt to get a token, since we have never used this accessor
    // before, it's guaranteed that we will need to make an HTTPS
    // request to the token provider to retrieve a token. This
    // will also happen if we want to get a token for a different
    // audience, or if the token has expired.
    let token = match sa_provider.get_id_token(audience).unwrap() {
        IdTokenOrRequest::AccessTokenRequest {
            request,
            audience_hash,
            ..
        } => {
            let access_token_response = execute_request(request).await;

            let id_token_request = sa_provider
                .get_id_token_with_access_token(audience, access_token_response)
                .unwrap();

            let id_token_response = execute_request(id_token_request).await;

            sa_provider
                .parse_id_token_response(audience_hash, id_token_response)
                .unwrap()
        }
        _ => unreachable!(),
    };

    // Uncomment this if you want to go to lunch and see an unreachable panic
    // when you get back
    // std::thread::sleep(std::time::Duration::from_secs(60 * 60))

    // Retrieving a token for the same scopes for which a token has been acquired
    // will use the cached token until it expires
    match sa_provider.get_id_token(audience).unwrap() {
        IdTokenOrRequest::IdToken(tk) => {
            assert_eq!(tk, token);
            println!(
                "cool, you were able to retrieve a token with aud {}!",
                audience,
            );
        }
        _ => unreachable!(),
    }
}

async fn execute_request(request: http::Request<Vec<u8>>) -> http::Response<Bytes> {
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

    builder.body(buffer).unwrap()
}
