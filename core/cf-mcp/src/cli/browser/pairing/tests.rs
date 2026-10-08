    use super::super::{
        build_logger, read_frame, write_frame, Logger, ENV_BROKER_SKIP_PEER_VERIFY, ENV_LOCK,
    };
    use super::{
        bind_notify_socket, run_notify_listener, serve_pair_request, NotifyPairRequest,
        PairResult, PairingHandle, PAIR_TIMEOUT,
    };
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// 临时 notify.sock 路径（唯一；进程 id + 纳秒时间戳）。
    fn temp_sock_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("coffer-pairing-{name}-{}-{nanos}", std::process::id()))
    }

    /// 测试 Logger（落临时文件，避免污染 stderr）。
    fn test_logger(name: &str) -> Logger {
        let path = temp_sock_path(name);
        build_logger(Some(path)).expect("test logger")
    }

    /// 测试门控 env：设置 `ENV_BROKER_SKIP_PEER_VERIFY=1`（notify App 鉴权跳过，
    /// mock App 在测试进程内），Drop 时恢复。
    struct SkipPeerGuard;

    impl SkipPeerGuard {
        fn new() -> Self {
            std::env::set_var(ENV_BROKER_SKIP_PEER_VERIFY, "1");
            SkipPeerGuard
        }
    }

    impl Drop for SkipPeerGuard {
        fn drop(&mut self) {
            std::env::remove_var(ENV_BROKER_SKIP_PEER_VERIFY);
        }
    }

    /// 建立 notify 监听线程 + mock App 客户端；返回 (broker 端, 扩展端, 句柄, App 线程)。
    ///
    /// socketpair 模拟 broker↔扩展连接：`broker` 端交给 [`serve_pair_request`]（broker
    /// 写 pair_result），`ext` 端为扩展侧（测试读 pair_result）。**两端都须存活**——
    /// 写进 `broker` 的数据落在 `ext` 的读缓冲，反之亦然；任一端被 drop 即对端读 EOF。
    ///
    /// mock App：重试 connect（覆盖 broker bind 启动窗）→ 读 pair_request → 交给
    /// `respond` 产出决策帧 → 写回 → 关闭（notify 线程随即清理连接态）。
    fn spawn_roundtrip(
        name: &str,
        respond: impl Fn(&[u8]) -> Vec<u8> + Send + 'static,
    ) -> (
        UnixStream,
        UnixStream,
        PairingHandle,
        std::thread::JoinHandle<()>,
    ) {
        let path = temp_sock_path(name);
        let listener = bind_notify_socket(&path).expect("bind notify.sock");
        let pk_b = "11".repeat(65);
        let psk_hex = "22".repeat(32);
        let handle = PairingHandle::new(pk_b, psk_hex);
        let thread_handle = handle.clone();
        let thread_path = path.clone();
        let thread_logger = test_logger(name);
        std::thread::spawn(move || {
            run_notify_listener(listener, thread_path, &thread_handle, thread_logger);
        });

        // mock App：重试 connect（覆盖 broker bind 启动窗）→ 读 pair_request → 回决策。
        let app_path = path.clone();
        let app = std::thread::spawn(move || {
            let mut stream = loop {
                match UnixStream::connect(&app_path) {
                    Ok(s) => break s,
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            };
            let frame = read_frame(&mut stream)
                .expect("App 应收到 pair_request 帧")
                .expect("EOF");
            let decision = respond(&frame);
            write_frame(&mut stream, &decision).expect("App 写决策");
            // 关闭连接：notify 线程读 EOF → 清理连接态。
        });

        let (broker, ext) = UnixStream::pair().expect("socketpair");
        (broker, ext, handle, app)
    }

    /// 解析扩展侧收到的 pair_result 帧（`ext` = socketpair 扩展端，broker 端写来的数据）。
    fn read_pair_result(stream: &mut UnixStream) -> serde_json::Value {
        let frame = read_frame(stream)
            .expect("扩展应收到 pair_result 帧")
            .expect("EOF");
        serde_json::from_slice(&frame).expect("pair_result 须为合法 JSON")
    }

    /// 构造扩展配对请求首帧。
    fn ext_pair_request_frame(browser: &str, extension_id: &str) -> Vec<u8> {
        serde_json::json!({
            "type": "pair_request",
            "browser": browser,
            "extension_id": extension_id,
        })
        .to_string()
        .into_bytes()
    }

    /// 构造批准决策（含 pk_b 原样转发）。
    fn approved_decision(request_id: u64, pk_b: &str) -> Vec<u8> {
        serde_json::json!({
            "type": "pair_decision",
            "request_id": request_id,
            "approved": true,
            "pk_b": pk_b,
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn notify_frames_encode_decode_roundtrip() {
        // pair_request 序列化字段（含 broker 自报 pk_b，D-B）。
        let req = NotifyPairRequest {
            r#type: "pair_request",
            request_id: 7,
            browser: "chrome".into(),
            extension_id: "abc123".into(),
            requested_at: 1234,
            pk_b: "ab".repeat(65),
        };
        let v: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
        assert_eq!(v["type"], "pair_request");
        assert_eq!(v["request_id"], 7);
        assert_eq!(v["browser"], "chrome");
        assert_eq!(v["extension_id"], "abc123");
        assert_eq!(v["requested_at"], 1234);
        assert_eq!(v["pk_b"], "ab".repeat(65));

        // pair_decision：批准含 pk_b / §2.3 严格 schema 无 pk_b 均可解析。
        let d: super::NotifyPairDecision = serde_json::from_str(
            r#"{"type":"pair_decision","request_id":7,"approved":true,"pk_b":"ab"}"#,
        )
        .unwrap();
        assert!(d.approved);
        assert_eq!(d.pk_b.as_deref(), Some("ab"));
        let d2: super::NotifyPairDecision = serde_json::from_str(
            r#"{"type":"pair_decision","request_id":8,"approved":false}"#,
        )
        .unwrap();
        assert!(!d2.approved);
        assert_eq!(d2.pk_b, None);

        // pair_result：批准/拒绝字段裁剪。
        let ok = PairResult::approved(9, "pskhex", "pkbhex");
        let v: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&ok).unwrap()).unwrap();
        assert_eq!(v["type"], "pair_result");
        assert_eq!(v["approved"], true);
        assert_eq!(v["psk"], "pskhex");
        assert_eq!(v["pk_b"], "pkbhex");
        assert!(v.get("reason").is_none(), "批准结果不含 reason");
        let no = PairResult::rejected(10, "timeout");
        let v: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&no).unwrap()).unwrap();
        assert_eq!(v["approved"], false);
        assert_eq!(v["reason"], "timeout");
        assert!(v.get("psk").is_none(), "拒绝结果不含 psk");
        assert!(v.get("pk_b").is_none(), "拒绝结果不含 pk_b");
    }

    /// 完整配对流：扩展 pair_request → App 批准（原样转发 pk_b）→ 扩展收到
    /// pair_result{approved:true, psk, pk_b}（mock App 走 notify.sock 往返）。
    #[test]
    fn pairing_approved_mock_app_roundtrip() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _skip = SkipPeerGuard::new();
        let (mut broker, mut ext, handle, _app) = spawn_roundtrip("approved", {
            // mock App：校验 pair_request 字段后回批准决策（request_id + pk_b 原样）。
            let expect_pk_b = "11".repeat(65);
            move |frame| {
                let v: serde_json::Value = serde_json::from_slice(frame).expect("合法 JSON");
                assert_eq!(v["type"], "pair_request");
                assert_eq!(v["browser"], "chrome");
                assert_eq!(v["extension_id"], "ext-abc");
                assert_eq!(v["pk_b"], expect_pk_b, "pair_request 须含 broker 自报 pk_b");
                let request_id = v["request_id"].as_u64().expect("request_id u64");
                approved_decision(request_id, &expect_pk_b)
            }
        });
        // 扩展侧发起配对（先等 mock App 连上，避免 app_unavailable 竞态）。
        let mut connected = false;
        for _ in 0..100 {
            if handle.app_connected() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(connected, "mock App 应连上 notify.sock");
        let result = serve_pair_request(&mut broker, &handle, &ext_pair_request_frame("chrome", "ext-abc"), &mut test_logger("approved-log"));
        assert!(matches!(result, super::super::ServerResult::Continue));
        let v = read_pair_result(&mut ext);
        assert_eq!(v["type"], "pair_result");
        assert_eq!(v["approved"], true);
        assert_eq!(v["psk"], "22".repeat(32), "PSK 由 stdin 注入，broker 下发 hex");
        assert_eq!(v["pk_b"], "11".repeat(65), "pair_result.pk_b = broker 自报公钥");
        assert!(v.get("reason").is_none());
    }

    /// App 拒绝 → pair_result{approved:false, reason:"rejected"}。
    #[test]
    fn pairing_rejected_mock_app() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _skip = SkipPeerGuard::new();
        let (mut broker, mut ext, handle, _app) = spawn_roundtrip("rejected", |frame| {
            let v: serde_json::Value = serde_json::from_slice(frame).unwrap();
            let request_id = v["request_id"].as_u64().unwrap();
            serde_json::json!({"type": "pair_decision", "request_id": request_id, "approved": false})
                .to_string()
                .into_bytes()
        });
        let mut connected = false;
        for _ in 0..100 {
            if handle.app_connected() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(connected);
        let result = serve_pair_request(&mut broker, &handle, &ext_pair_request_frame("chrome", "ext-abc"), &mut test_logger("rejected-log"));
        assert!(matches!(result, super::super::ServerResult::Continue));
        let v = read_pair_result(&mut ext);
        assert_eq!(v["approved"], false);
        assert_eq!(v["reason"], "rejected");
    }

    /// §2.3 严格 schema 决策（无 pk_b 字段）→ broker 回落自身身份公钥，批准成立。
    #[test]
    fn pairing_approved_without_pk_b_falls_back_to_broker_key() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _skip = SkipPeerGuard::new();
        let (mut broker, mut ext, handle, _app) = spawn_roundtrip("no-pk-b", |frame| {
            let v: serde_json::Value = serde_json::from_slice(frame).unwrap();
            let request_id = v["request_id"].as_u64().unwrap();
            serde_json::json!({"type": "pair_decision", "request_id": request_id, "approved": true})
                .to_string()
                .into_bytes()
        });
        let mut connected = false;
        for _ in 0..100 {
            if handle.app_connected() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(connected);
        let result = serve_pair_request(&mut broker, &handle, &ext_pair_request_frame("firefox", "ext-ff"), &mut test_logger("no-pk-b-log"));
        assert!(matches!(result, super::super::ServerResult::Continue));
        let v = read_pair_result(&mut ext);
        assert_eq!(v["approved"], true);
        assert_eq!(v["pk_b"], "11".repeat(65), "缺 pk_b 时回落 broker 自报公钥");
    }

    /// App 原样转发失配 pk_b（与 broker 身份不一致）→ fail-closed 拒绝。
    #[test]
    fn pairing_mismatched_pk_b_rejected() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _skip = SkipPeerGuard::new();
        let (mut broker, mut ext, handle, _app) = spawn_roundtrip("mismatch", |frame| {
            let v: serde_json::Value = serde_json::from_slice(frame).unwrap();
            let request_id = v["request_id"].as_u64().unwrap();
            approved_decision(request_id, &"ff".repeat(65)) // 与 broker 身份不一致
        });
        let mut connected = false;
        for _ in 0..100 {
            if handle.app_connected() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(connected);
        let result = serve_pair_request(&mut broker, &handle, &ext_pair_request_frame("chrome", "ext-abc"), &mut test_logger("mismatch-log"));
        assert!(matches!(result, super::super::ServerResult::Continue));
        let v = read_pair_result(&mut ext);
        assert_eq!(v["approved"], false);
        assert_eq!(v["reason"], "rejected");
    }

    /// App 未连接 notify.sock（决策⑥：App 未启动/离线）→ 立即 app_unavailable。
    #[test]
    fn pairing_app_unavailable_when_no_app() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let handle = PairingHandle::new("11".repeat(65), "22".repeat(32));
        let (mut broker, mut ext) = UnixStream::pair().expect("socketpair");
        let result = serve_pair_request(&mut broker, &handle, &ext_pair_request_frame("edge", "ext-edge"), &mut test_logger("no-app-log"));
        assert!(matches!(result, super::super::ServerResult::Continue));
        let v = read_pair_result(&mut ext);
        assert_eq!(v["approved"], false);
        assert_eq!(v["reason"], "app_unavailable");
    }

    /// 挂起超时（测试注入短超时）：App 收到 pair_cancel{timeout} 关框，扩展收到
    /// pair_result{approved:false, reason:"timeout"}。
    #[test]
    fn pairing_timeout_sends_cancel_and_rejects() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _skip = SkipPeerGuard::new();
        let path = temp_sock_path("timeout");
        let listener = bind_notify_socket(&path).expect("bind notify.sock");
        let handle = PairingHandle::with_timeout("11".repeat(65), "22".repeat(32), Duration::from_millis(150));
        let thread_handle = handle.clone();
        let thread_path = path.clone();
        let thread_logger = test_logger("timeout-thread");
        std::thread::spawn(move || {
            run_notify_listener(listener, thread_path, &thread_handle, thread_logger);
        });

        // mock App：连上后读 pair_request，再读 pair_cancel{timeout}，断言后关闭。
        let app_path = path.clone();
        let app = std::thread::spawn(move || {
            let mut stream = loop {
                match UnixStream::connect(&app_path) {
                    Ok(s) => break s,
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            };
            let req = read_frame(&mut stream).expect("App 读 pair_request").expect("EOF");
            let v: serde_json::Value = serde_json::from_slice(&req).unwrap();
            assert_eq!(v["type"], "pair_request");
            let cancel = read_frame(&mut stream)
                .expect("App 应收到 pair_cancel")
                .expect("EOF");
            let cv: serde_json::Value = serde_json::from_slice(&cancel).unwrap();
            assert_eq!(cv["type"], "pair_cancel");
            assert_eq!(cv["reason"], "timeout");
        });

        let mut connected = false;
        for _ in 0..100 {
            if handle.app_connected() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(connected);
        let (mut broker, mut ext) = UnixStream::pair().expect("socketpair");
        let result = serve_pair_request(&mut broker, &handle, &ext_pair_request_frame("chrome", "ext-abc"), &mut test_logger("timeout-log"));
        assert!(matches!(result, super::super::ServerResult::Continue));
        let v = read_pair_result(&mut ext);
        assert_eq!(v["approved"], false);
        assert_eq!(v["reason"], "timeout");
        app.join().expect("mock App 线程正常退出");
    }

    /// 非法扩展配对请求帧（缺 browser/extension_id / 未知 type）→ 拒连不 panic。
    #[test]
    fn pairing_malformed_extension_request_rejected() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let handle = PairingHandle::new("11".repeat(65), "22".repeat(32));
        let (mut ext, ext_peer) = UnixStream::pair().expect("socketpair");
        // 关闭对端 → ext 读立即 EOF（非法帧不写 pair_result，不能悬着阻塞）。
        drop(ext_peer);
        for frame in [
            br#"{"type":"pair_request","browser":"chrome"}"#.to_vec(), // 缺 extension_id
            br#"{"type":"pair_request","browser":"","extension_id":""}"#.to_vec(),
            br#"{"type":"nope","browser":"chrome","extension_id":"x"}"#.to_vec(),
            br#"not json"#.to_vec(),
        ] {
            let result = serve_pair_request(&mut ext, &handle, &frame, &mut test_logger("malformed-log"));
            assert!(matches!(result, super::super::ServerResult::Continue));
            // 非法帧直接返回，不写 pair_result（serve_connection 拒连语义）。
            assert!(read_frame(&mut ext).expect("读").is_none(), "非法帧不应写 pair_result");
        }
    }

    /// 配对超时缺省值 = 30s（docs/31 §2.4 裁定 ③ 契约回归；2026-10-08 用户裁定 120s→30s）。
    #[test]
    fn default_pair_timeout_is_30s() {
        assert_eq!(PAIR_TIMEOUT, Duration::from_secs(30));
    }
