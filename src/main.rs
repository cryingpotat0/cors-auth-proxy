use actix_cors::Cors;
use actix_web::rt::time::sleep;
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer};
use chrono::Utc;
use clap::{App as ClapApp, Arg};
use log::{error, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rusqlite::{params, Connection, Result as SqliteResult};
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DB_PATH: &str = "cors_proxy.db";
const SUBDOMAIN_LENGTH: usize = 13;

struct AppState {
    db: Arc<Mutex<Connection>>,
    expiration_minutes: i64,
    domain: String,
    api_key: String,
}

fn generate_random_string() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(SUBDOMAIN_LENGTH)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

fn create_table(conn: &Connection) -> SqliteResult<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS subdomains (
            prefix TEXT PRIMARY KEY,
            touched_at TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

async fn create_subdomain(data: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let api_key = match req.headers().get("Authorization") {
        Some(value) => value.to_str().unwrap_or(""),
        None => return HttpResponse::Unauthorized().finish(),
    };

    if api_key != data.api_key {
        // Prevent timing attacks.
        sleep(Duration::from_secs(1)).await;
        return HttpResponse::Unauthorized().finish();
    }

    let prefix = generate_random_string();
    let now = Utc::now().to_rfc3339();

    let db = data.db.lock();
    match db {
        Ok(db) => {
            match db.execute(
                "INSERT INTO subdomains (prefix, touched_at) VALUES (?, ?)",
                params![prefix, now],
            ) {
                Ok(_) => HttpResponse::Ok()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .append_header((
                        "Access-Control-Allow-Methods",
                        "GET, POST, PUT, DELETE, OPTIONS",
                    ))
                    .body(format!("{}.{}", prefix, data.domain)),
                Err(_) => HttpResponse::InternalServerError().finish(),
            }
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

async fn proxy(
    data: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> Result<HttpResponse, Error> {
    let host = req.connection_info().host().to_string();
    // Pretend the subdomain is the third from last element on the host. So we are a proxy hosted
    // at {proxy_url}.{subdomain}.something.example.com OR
    // {subdomain}.something.example.com/{proxy_url}

    // Split the host into parts
    let host_parts: Vec<&str> = host.split('.').collect();

    let subdomain = if host_parts.len() >= 4 {
        host_parts[host_parts.len() - 4].to_string()
    } else {
        return Err(actix_web::error::ErrorInternalServerError(format!(
            "Host {:?} should be of length 3 or more",
            host
        )));
    };

    // Check if subdomain exists and is not expired
    let result: SqliteResult<String> = data.db.lock().map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Error getting lock: {}", e))
    })?.query_row(
        "SELECT prefix FROM subdomains WHERE prefix = ? AND datetime(touched_at) > datetime('now', ?)",
        params![subdomain, format!("-{} minutes", data.expiration_minutes)],
        |row| Ok(row.get(0)),
    ).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("Error querying database: {}", e))
    })?;

    info!("Subdomain: {}", subdomain);

    match result {
        Ok(_) => {
            // Update touched_at
            let now = Utc::now().to_rfc3339();
            data.db
                .lock()
                .map_err(|e| {
                    actix_web::error::ErrorInternalServerError(format!("Error getting lock: {}", e))
                })?
                .execute(
                    "UPDATE subdomains SET touched_at = ? WHERE prefix = ?",
                    params![now, subdomain],
                )
                .map_err(actix_web::error::ErrorInternalServerError)?;

            // Proxy the request
            let client = reqwest::Client::new();
            let url = if host_parts.len() > 4 {
                format!(
                    "https://{}{}",
                    host_parts[0..host_parts.len() - 4].join("."),
                    req.uri()
                )
            } else {
                format!("https://{}", req.uri().to_string().trim_start_matches('/'))
            };
            info!("Proxying request to {} with method {}", url, req.method());

            let mut proxy_req = client.request(req.method().clone(), &url);

            // Forward headers
            for (header_name, header_value) in req.headers().iter().filter(|(h, _)| *h != "host") {
                proxy_req = proxy_req.header(header_name.clone(), header_value.clone());
            }

            // Forward body
            proxy_req = proxy_req.body(body);
            info!("Request forwarded");

            // Send the request
            let proxy_res = proxy_req.send().await.map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("Error sending request: {}", e))
            })?;

            info!("Response received");

            // Create response and copy status
            let mut client_resp = HttpResponse::build(proxy_res.status());

            // Copy headers
            for (header_name, header_value) in proxy_res.headers().iter() {
                if header_name != "access-control-allow-origin" {
                    info!("Returning header: {:?} = {:?}", header_name, header_value);
                    client_resp.append_header((header_name.clone(), header_value.clone()));
                }
            }

            for (header_name, header_value) in [
                ("Access-Control-Allow-Origin", "*"),
                (
                    "Access-Control-Allow-Methods",
                    "GET, POST, PUT, DELETE, OPTIONS",
                ),
                ("Access-Control-Allow-Headers", "*"),
            ] {
                info!("Returning header: {:?} = {:?}", header_name, header_value);
                client_resp.append_header((header_name, header_value));
            }

            // Forward body
            Ok(client_resp.body(proxy_res.bytes().await.map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("Error reading body: {}", e))
            })?))
        }
        Err(_) => {
            // Delete expired subdomain
            data.db
                .lock()
                .map_err(|e| {
                    actix_web::error::ErrorInternalServerError(format!("Error getting lock: {}", e))
                })?
                .execute(
                    "DELETE FROM subdomains WHERE prefix = ?",
                    params![subdomain],
                )
                .map_err(actix_web::error::ErrorInternalServerError)?;
            Ok(HttpResponse::NotFound().finish())
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let matches = ClapApp::new("CORS Proxy")
        .arg(
            Arg::with_name("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Sets the port to run the server on")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("expiration")
                .short('e')
                .long("expiration")
                .value_name("MINUTES")
                .help("Sets the expiration time for subdomains in minutes")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("generate")
                .short('g')
                .long("generate")
                .help("Generates a temporary URL for testing"),
        )
        .arg(
            Arg::with_name("domain")
                .short('d')
                .long("domain")
                .value_name("DOMAIN")
                .help("Sets the domain for the subdomains")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("local")
                .help("Run on localhost")
                .short('l')
                .long("local")
                .value_name("LOCAL")
                .takes_value(true),
        )
        .get_matches();

    let port = matches.value_of("port").unwrap_or("8080").parse().unwrap();
    let expiration_minutes = matches
        .value_of("expiration")
        .unwrap_or("60") // 1 hour expiration.
        .parse()
        .unwrap();

    let env_domain = env::var("SUBDOMAIN").unwrap_or("example.com".to_string());
    let domain = match matches.value_of("domain") {
        Some(d) => d,
        None => &env_domain,
    };

    let api_key = env::var("API_KEY").expect("API_KEY to be set");
    if api_key.is_empty() {
        panic!("API_KEY is empty");
    }

    let conn =
        Connection::open(DB_PATH).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    create_table(&conn).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    if matches.is_present("generate") {
        let prefix = generate_random_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO subdomains (prefix, touched_at) VALUES (?, ?)",
            params![prefix, now],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        println!("Temporary URL: https://{}.cors.cryingpotato.com", prefix);
        return Ok(());
    }

    let state = web::Data::new(AppState {
        api_key,
        db: Arc::new(conn.into()),
        expiration_minutes,
        domain: domain.to_string(),
    });

    let bind_url = if matches.is_present("local") {
        "127.0.0.1"
    } else {
        "0.0.0.0"
    };

    info!("Listening on {}:{}", bind_url, port);
    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .app_data(state.clone())
            .wrap(cors)
            .route("/url", web::get().to(create_subdomain))
            .route("/url", web::get().to(create_subdomain))
            .default_service(web::to(proxy))
    })
    .bind((bind_url, port))?
    .run()
    .await
}
