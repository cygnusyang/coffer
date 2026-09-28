//! FR-6.4 / FR-6.5 / FR-6.6 安全体检纯函数（docs/03 §8 规则集
//! AUD-04 / AUD-05 / AUD-06，docs/01 §5-F）。
//!
//! 本模块与 [`crate::watchtower`] 同属**纯计算层**：不依赖 `cf-store`、
//! 无网络、无 IO，明文即用即弃；体检编排在 cf-session（FR-6.7）。
//!
//! - **FR-6.4 / AUD-04 陈旧密码**（低严重度，Must）：`updated_at` 距今
//!   天数 > 阈值（默认 [`DEFAULT_STALE_DAYS`] = 365，可配置）；
//! - **FR-6.5 / AUD-05 泄露启发式**（Should，非门禁）：**不查询在线泄露
//!   库**（X-07，零网络原则）。基于内置常见密码 SHA-256 指纹字典与本地
//!   规则做启发式命中，逐级标注置信度（漏报优先）。**能力缺口必须向用户
//!   明示**：本结果不覆盖真实泄露事件（docs/03 §8 能力缺口声明，需同时
//!   出现在产品文档、首次运行引导、报告页脚）；
//! - **FR-6.6 / AUD-06 无 2FA 提示**（Should，非门禁）：条目 URL 域名在
//!   本地 2FA 支持域名白名单（[`TWO_FA_DOMAINS`]，覆盖范围有限）中且条目
//!   未配置 TOTP → 提示启用 2FA。
//!
//! 弱 URL（FR-6.3 / AUD-03）已在 [`crate::watchtower`] 实现，本模块不重复。

use sha2::{Digest, Sha256};

/// AUD-04 陈旧密码默认阈值（天，docs/03 §8：默认 365，可配置）。
pub const DEFAULT_STALE_DAYS: i64 = 365;

/// 一天的秒数（Unix 秒时间戳换算）。
const SECS_PER_DAY: i64 = 86_400;

/// 泄露启发式的命中规则（FR-6.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonPasswordRule {
    /// 明文精确命中内置字典（docs/03 §8 AUD-05 字典命中）。
    DictionaryExact,
    /// 常见 leet 替换归一后命中字典（如 `dr4g0n` → `dragon`）。
    LeetNormalized,
    /// 8 位纯数字生日形态（YYYYMMDD）。
    BirthdayPattern,
    /// 包含键盘行序列（qwerty 等）。
    KeyboardSequence,
}

/// 启发式置信度（漏报优先：只报有明确形态依据的项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// 低置信度（形态启发，仅提示）。
    Low,
    /// 中置信度（leet 归一后命中字典）。
    Medium,
    /// 高置信度（明文精确命中字典）。
    High,
}

/// 单条泄露启发式命中（FR-6.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonPasswordHit {
    /// 所属条目 id。
    pub item_id: String,
    /// 命中规则。
    pub rule: CommonPasswordRule,
    /// 置信度。
    pub confidence: Confidence,
}

/// 陈旧密码检测（FR-6.4 / AUD-04）：`updated_at` 距今天数**大于**阈值
/// （默认 [`DEFAULT_STALE_DAYS`]，可配置）的条目 id。
///
/// 输入为 `(item_id, updated_at_unix_sec)` 对；`now` 由调用方注入
/// （Unix 秒），保持纯函数无时钟依赖。输出保持输入顺序并去重。
/// 阈值边界：恰好等于阈值不报（措辞为"> 阈值"）；`updated_at` 在未来
/// （时钟偏移）不报。
#[must_use]
pub fn find_stale_passwords(
    entries: &[(String, i64)],
    now: i64,
    threshold_days: i64,
) -> Vec<String> {
    let mut stale: Vec<String> = Vec::new();
    for (item_id, updated_at) in entries {
        let days_elapsed = now.saturating_sub(*updated_at) / SECS_PER_DAY;
        if days_elapsed > threshold_days && !stale.iter().any(|seen| seen == item_id) {
            stale.push(item_id.clone());
        }
    }
    stale
}

/// 泄露启发式（FR-6.5 / AUD-05，Should 非门禁）。
///
/// 判定按置信度从高到低，**每个条目最多产出一条命中**（同一条目多段
/// 密码时取置信度最高者，同置信度取先出现者——控制噪音）：
///
/// 1. 明文精确命中内置字典 → [`Confidence::High`]；
/// 2. leet 归一（`@→a`、`0→o`、`1→i`、`3→e`、`4→a`、`5→s`、`7→t`、
///    `8→b`、`$→s`）后命中 → [`Confidence::Medium`]；
/// 3. 8 位纯数字生日形态（YYYYMMDD，宽松校验年 1900–2099 / 月 01–12 /
///    日 01–31）→ [`Confidence::Low`]；
/// 4. 包含键盘行序列（qwerty 等）→ [`Confidence::Low`]。
///
/// 输入为 `(item_id, 明文密码)` 对；明文仅在本函数内流转，即用即弃。
/// 本结果**不覆盖真实泄露事件**（FR-6.5 能力缺口声明）。
#[must_use]
pub fn find_common_passwords(items: &[(String, String)]) -> Vec<CommonPasswordHit> {
    let mut hits: Vec<CommonPasswordHit> = Vec::new();
    for (item_id, password) in items {
        let Some((rule, confidence)) = evaluate_common_password(password) else {
            continue;
        };
        if let Some(existing) = hits.iter_mut().find(|h| h.item_id == *item_id) {
            // 同条目多段密码：保留置信度更高者（同置信度保先出现者）
            if confidence > existing.confidence {
                existing.rule = rule;
                existing.confidence = confidence;
            }
        } else {
            hits.push(CommonPasswordHit {
                item_id: item_id.clone(),
                rule,
                confidence,
            });
        }
    }
    hits
}

/// 单条密码的启发式评估：返回首个（最高优先）命中的规则与置信度。
fn evaluate_common_password(password: &str) -> Option<(CommonPasswordRule, Confidence)> {
    if dict_hit(password) {
        return Some((CommonPasswordRule::DictionaryExact, Confidence::High));
    }
    if dict_hit(&leet_normalize(password)) {
        return Some((CommonPasswordRule::LeetNormalized, Confidence::Medium));
    }
    if is_birthday_form(password) {
        return Some((CommonPasswordRule::BirthdayPattern, Confidence::Low));
    }
    if is_keyboard_sequence(password) {
        return Some((CommonPasswordRule::KeyboardSequence, Confidence::Low));
    }
    None
}

/// 计算字符串的 SHA-256 小写十六进制指纹。
fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('x'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('x'));
    }
    hex
}

/// 明文（或归一化文本）是否命中内置常见密码指纹字典。
///
/// 字典为**排序数组 + 二分查找**（编译期常量，无运行时初始化开销）；
/// 字典本身不是秘密、不加密（docs/03 §8 AUD-05）。
fn dict_hit(s: &str) -> bool {
    COMMON_PASSWORD_SHA256.binary_search(&sha256_hex(s).as_str()).is_ok()
}

/// 常见 leet 替换归一（FR-6.5 启发式；单遍映射，不做多重展开——
/// 漏报优先）。`1→i`（`1→l` 歧义映射刻意不采纳，避免双射不确定）。
fn leet_normalize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '@' => 'a',
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '$' => 's',
            other => other,
        })
        .collect()
}

/// 8 位纯数字生日形态（YYYYMMDD，宽松校验：年 1900–2099、月 01–12、
/// 日 01–31；不校验历法真实性——启发式，宁可漏报）。
fn is_birthday_form(s: &str) -> bool {
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let year: i32 = s[..4].parse().unwrap_or(0);
    let month: i32 = s[4..6].parse().unwrap_or(0);
    let day: i32 = s[6..].parse().unwrap_or(0);
    (1900..=2099).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// 键盘行序列（FR-6.5 启发式；小写匹配）。
const KEYBOARD_SEQUENCES: [&str; 8] = [
    "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "poiuyt", "lkjhgf", "mnbvcx",
];

/// 是否包含键盘行序列。
fn is_keyboard_sequence(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    KEYBOARD_SEQUENCES.iter().any(|seq| lower.contains(seq))
}

/// 内置常见密码 SHA-256 指纹字典（FR-6.5 / AUD-05，**离线**）。
///
/// 来源依据：公开常见密码词表（SecLists / NordRock 类 top 常见密码集合）
/// 整理的 171 条高频条目（去重后），每条存 SHA-256 十六进制指纹而非明文
/// （避免常见密码明文出现在二进制中）。**字典本身不是秘密**，不加密
/// （docs/03 §8 AUD-05）；覆盖有限，漏报优先，随版本可扩充。
const COMMON_PASSWORD_SHA256: [&str; 171] = [
    "000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f",
    "00390de2b7074071bb6494e818e84884ef6331ceb0b1e70948bde3ef4ba57b92",
    "02d2c8a77642c129484a576baff80dd186b1ae30e0551ed15d07165e895f420a",
    "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
    "04e77bf8f95cb3e1a36a59d1e93857c411930db646b46c218a0352e432023cf2",
    "0522a55e2d5f0993a3d66d28864b2862a7218a75ea7968b075333434404485c3",
    "057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86",
    "059a00192592d5444bc0caad7203f98b506332e2cf7abb35d684ea9bf7c18f08",
    "0729563253bc11cb72714d61132adfe7ba2346b581b02546c9ac4a65fc0c02d8",
    "083354f64c19aaf064f902704265178aca70548367b13f1a9b75dde022052571",
    "094dacfa4ae26448b7e7fdb6bf45b639ea9c9de2f942aa42310305f0657f9c61",
    "0a0667865bc17f9d624bcf11088057bbab46336e7dae65f3d5366f4f7a18333e",
    "0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e",
    "0b378c4f890f52055cb340edf238857d2fc51833ad2cbfd5b0ee14c394fd67d0",
    "0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4",
    "0d6be69b264717f2dd33652e212b173104b4a647b7c11ae72e9885f11cd312fb",
    "1134e4f4a13b06aeaa8471f934589a3e180bf3fe432e32e1f9454e76a90077e7",
    "136c67657614311f32238751044a0a3c0294f2a521e573afa8e496992d3786ba",
    "13b1f7ec5beaefc781e43a3b344371cd49923a8a05edd71844b92f56f6a08d38",
    "13ed070478ef62c3a7baa36c8d042a9d1cdc0fcbb2af93a795f2ad20ad6e9cb5",
    "143705b2daf4782f008a1fc7aedddf3ee66e8b42d295cf07cdc015ab93b90be9",
    "1532e76dbe9d43d0dea98c331ca5ae8a65c5e8e8b99d3e2a42ae989356f6242a",
    "15c6d611193988e468c7431229c59ce13b0407fba24f11d36c42680d7fa11e98",
    "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
    "1718c24b10aeb8099e3fc44960ab6949ab76a267352459f203ea1036bec382c2",
    "18138372fad4b94533cd4881f03dc6c69296dd897234e0cee83f727e2e6b1f63",
    "1a6c02c940b633fbdc7629086c29be7c06316fa44f84192e8d6984d85c513469",
    "1b4c9133da73a711322404314402765ab0d23fd362a167d6f0c65bb215113d94",
    "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032",
    "1ecd41c03ef78bd6daeaa6bb008896607a8413bf8ba6266be80327554b370a9e",
    "203b70b5ae883932161bbd0bded9357e763e63afce98b16230be33f0b94c2cc5",
    "20f645c703944a0027acf6fad92ec465247842450605c5406b50676ff0dcd5ea",
    "27df9ed9a477af0fcfe369c8ef3474a75cebf357d8b421ca40f1de6cfd4cbb06",
    "280d44ab1e9f79b5cce2dd4f58f5fe91f0fbacdac9f7447dffc318ceb79f2d02",
    "284fff3bd254b48cca05a8bfc4fad69e05cad0d086513a034a66a118829e6fa4",
    "2a057642222a878bc360f52f8e1f0dfd2af93196f123269397423155a4ec4884",
    "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "308738b8195da46d65c96f4ee3909032e27c818d8a079bccb5a1ef62e8daaa45",
    "30c5461fc27b84f1f1ad0a83162a26882b22d11cdfa45978dd21c810056e8d0e",
    "30caae2fcb7c34ecadfddc45e0a27e9103bd7cfc87730d7818cc096b1266a683",
    "337b8d2c1e132acd75171f1acf0e73b20bc9541720d5003813f59ef0ad51f86f",
    "34550715062af006ac4fab288de67ecb44793c3a05c475227241535f6ef7a81b",
    "3721e1a2ad55f5ac10498a98a9069121be19ea3363cf44f18f10008728c360ad",
    "37290d74ac4d186e3a8e5785d259d2ec04fac91ae28092e7620ec8bc99e830aa",
    "37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f",
    "37bfdcb4c50793a6286fa0efe07b9e6bba8605b2c32e329fb9f71f225545f027",
    "3972905cc58310b37c7989feb13592ea71cf0902fd0fe4415782ece0c469d22c",
    "3b0fe0d342e9fa16a5c68dbba33f2e63c024f72a9d4c1ce1028570101d5229ff",
    "3d14c2d4e4ced81e459e4ace7c01466a700000fb94a3bbe944a55fb92693e879",
    "3d59f7548e1af2151b64135003ce63c0a484c26b9b8b166a7b1c1805ec34b00a",
    "3ea87a56da3844b420ec2925ae922bc731ec16a4fc44dcbeafdad49b0e61d39c",
    "3f08d8fadb4b67fb056623565edbbc2c788091d78fd24cbc473fce3043ce3473",
    "4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9",
    "428821350e9691491f616b754cd8315fb86d797ab35d843479e732ef90665324",
    "43ff792d79f75890d3c5181739783889bf9ef4a9397cc8d2fc0ea543ce5a30f7",
    "472bbe83616e93d3c09a79103ae47d8f71e3d35a966d6e8b22f743218d04171d",
    "4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2",
    "481f6cc0511143ccdd7e2d1b1b94faf0a700a8b49cd13922a70b5ae28acaa8c5",
    "4f9f10b304cfe9b2b11fcb1387f694e18f08ea358c7e9f567434d3ad6cbd7fc4",
    "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
    "519ba91a5a5b4afb9dc66f8805ce8c442b6576316c19c6896af2fa9bda6aff71",
    "54482595177116e6103b076dbf30648e5d0537dd1ed9cf5ae4562fa8a700d47b",
    "5600715f42bf51c40dc330d750cd996f58fead4ddea56466ce7498d17801b3a5",
    "58e989955f4b358feb6e4580eff3c7a04f5d9fa2d8381a6479cdfffa4cbe1211",
    "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",
    "59945da25d2521045b4bc84db7d5fd44b2c5511fe7cc247a8ce5a79bcd74a1c2",
    "5c80565db6f29da0b01aa12522c37b32f121cbe47a861ef7f006cb22922dffa1",
    "5d2d3ceb7abe552344276d47d36a8175b7aeb250a9bf0bf00e850cd23ecf2e43",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "615ed7fb1504b0c724a296d7a69e6c7b2f9ea2c57c1d8206c5afdf392ebdfd25",
    "622a494d3ea8c7ba2fed4f37909f14d9b50ab412322de39be62c8d6c2418bfca",
    "63640264849a87c90356129d99ea165e37aa5fabc1fea46906df1a7ca50db492",
    "6382deaf1f5dc6e792b76db4a4a7bf2ba468884e000b25e7928e621e27fb23cb",
    "6460662e217c7a9f899208dd70a2c28abdea42f128666a9b78e6c0c064846493",
    "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5",
    "686f746a95b6f836d7d70567c302c3f9ebb5ee0def3d1220ee9d4e9f34f5e131",
    "68c51aba8bd761fec11657cd7781d9abac8ef27ecaba0320b55961b8e49001b5",
    "697b62c258b2260d0a744352b5fd5d2be48b71f60f67ce200f05e9b9afeed7e5",
    "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
    "7182a571ddbe4752823cf4b8c38fd98720ae3ffac2aea0c22dd462fa8f6f0d9c",
    "72ab994fa2eb426c051ef59cad617750bfe06d7cf6311285ff79c19c32afd236",
    "73cd1b16c4fb83061ad18a0b29b9643a68d4640075a466dc9e51682f84a847f5",
    "74fca0325b5fdb3a34badb40a2581cfbd5344187e8d3432952a5abc0929c1246",
    "78cde64c3e47f2cbfd9da721f54aacde33779916683c79de86962898feefac21",
    "7c2523c985881fb2c2b4cfbe917eb12c4c4b61e898ad4e7160cfca487ca3c4f3",
    "7d824ad37e366f330ef3d3bafb8dc8b18a5b07622e2830eac5966339d98a94b0",
    "80d41c54a8ce6d26ae0bdd509db6b187140cae39b4b771269a0d006b0620e2d2",
    "81c9d6128b5fcd7bbe4ba65c177388ff767a2017f971c053dcaa6f32b4d6a758",
    "8360632a2b41498c6f979a15aced6655a2857f259533e77106228c683c4ab5af",
    "84308bea454057aa509a12fbd5212988973d7cd513bc555a24a06dd2cc72e39e",
    "84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec",
    "85738f8f9a7f1b04b5329c590ebcb9e425925c6d0984089c43a022de4f19c281",
    "8588310a98676af6e22563c1559e1ae20f85950792bdcd0c8f334867c54581cd",
    "873ac9ffea4dd04fa719e8920cd6938f0c23cd678af330939cff53c3d2855f34",
    "88b1cca59060320e5e5662a7da636884eb7580f4dc7e22cfb6f88b8f99045a71",
    "8a9bcf1e51e812d0af8465a8dbcc9f741064bf0af3b3d08e6b0246437c19f7fb",
    "8bb0cf6eb9b17d0f7d22b456f121257dc1254e1f01665370476383ea776df414",
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
    "8cbbcf29d9cef89675c5f5c1dcfe827d0570416a5aaba30dd0de159661ad905b",
    "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    "8e0a1b0ada42172886fd1297e25abf99f14396a9400acbd5f20da20289cff02f",
    "8f0e2f76e22b43e2855189877e7dc1e1e7d98c226c95db247cd1d547928334a9",
    "8f27f432fcbaa4b5180a1cc7a8fa166a93cda3c1bce6f19922dd519d02f4bb39",
    "917ebb3396b2ff2e27b75e3fe421b1edc07b998f74350472f3abc5c6620a68db",
    "91b4d142823f7d20c5f08df69122de43f35f057a988d9619f6d3138485c9a203",
    "92c7d71b95dc6540fc58e891dbe649fe72ae5e93b5f42fd7fbdeefe6cef3e51d",
    "94edf28c6d6da38fd35d7ad53e485307f89fbeaf120485c8d17a43f323deee71",
    "968e2d5b08687bf42997461cbdef6c844eabbf04f440cee888c95b864c2a4bcc",
    "96cae35ce8a9b0244178bf28e4966c2ce1b8385723a96a6b838858cdd6ca0a1e",
    "9c15e816069946fbd20bed0935dd9d8e34d64034d657a2b852f8b66ad91af5b6",
    "9cdc207a55907b520b57a948f5c100aff19cd539bd3cdf85a48623357e1f3f55",
    "9ce8db922a8f4a7abd859adee70bd8b7a63321265487da54cf4bed6a69eb3e1b",
    "9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280",
    "9e861941ad8bf5bcb649e5fde92d712528200a216018c2437371498e6ab7683d",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "a01edad91c00abe7be5b72b5e36bf4ce3c6f26e8bce3340eba365642813ab8b6",
    "a03c32fcd351cba2d9738622b083bed022ef07793bd92b59faea0207653f371d",
    "a0561fd649cdb6baa784055f051bad796ea0afef17fca38219549deeba4e8c1a",
    "a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95",
    "a320480f534776bddb5cdb54b1e93d210a3c7d199e80a23c1b2178497b184c76",
    "a54e71f0e17f5aaf7946e66ab42cf3b1fd4e61d60581736c9f0eb1c3f794eb7c",
    "a76b7f25b6ba5ec51bd9fa42f4143b63c2495996e783baa4d9f8459d314f6ad2",
    "a92f6bdb75789bccc118adfcf704029aa58063c604bab4fcdd9cd126ef9b69af",
    "a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223",
    "a9c43be948c5cabd56ef2bacffb77cdaa5eec49dd5eb0cc4129cf3eda5f0e74c",
    "aa97302150fce811425cd84537028a5afbe37e3f1362ad45a51d467e17afdc9c",
    "abc529a4b673cbbbc532e584706cb8137be876ad53269df3b97fbd40fc76fe57",
    "adce98918a37c6a158bebe38d61538c8dc2c636622390e8274e374c5135196d8",
    "af41e68e1309fa29a5044cbdc36b90a3821d8807e68c7675a6c495112bc8a55f",
    "b07f3fc75999732d068489fad851944e09aa103288130173555c0ef2a6c13dd6",
    "b493d48364afe44d11c0165cf470a4164d1e2609911ef998be868d46ade3de4e",
    "b6650cb5a7e308c12e617a05e31a2837e88bf51d1fe6614cb896127432fe257c",
    "b77c4e8ab2fb5ce536bb35289abd92d810f235a97032fa7f4701073d8610ae78",
    "b8510932dad3ddf0fc34661a0caf6674e5c0d672e3930c6a736424d4df0e8016",
    "b9dd960c1753459a78115d3cb845a57d924b6877e805b08bd01086ccdf34433c",
    "ba723435a66e490530c3efdfeac868e06fde6e35dcc43fa8528fb1b2c9411ef5",
    "baff4fb62c8b1c5a7934aeb176930b58670bc06d1db866b398b7a511a6b90f25",
    "bbdefa2950f49882f295b1285d4fa9dec45fc4144bfb07ee6acc68762d12c2e3",
    "bcb15f821479b4d5772bd0ca866c00ad5f926e3580720659cc80d39c9d09802a",
    "c06b0cfe0cc5e900c57784484094331f095bf441995c3c31ea6c75691c786c35",
    "c0c4a69b17a7955ac230bfc8db4a123eaa956ccf3c0022e68b8d4e2f5b699d1f",
    "c64975ba3cf3f9cd58459710b0a42369f34b0759c9967fb5a47eea488e8bea79",
    "c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646",
    "c9344c5f1079f7ce9b007e604829f7e8e4516e9132e098ebd58e2cc7f2a5fd4c",
    "cbc62794911ff31b2864ecd3dbbbee7ebcb7ea41c5a42e2cba377f3cfdb42811",
    "cbeaff314ef5ad032caa60ee2e8d8144ae52a8572c7d6f75631f3bd4080a7b16",
    "ce5ca673d13b36118d54a7cf13aeb0ca012383bf771e713421b4d1fd841f539a",
    "d38681074467c0bc147b17a9a12b9efa8cc10bcf545f5b0bccccf5a93c4a2b79",
    "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1",
    "d979885447a413abb6d606a5d0f45c3b7809e6fde2c83f0df3426f1fc9bfed97",
    "daaad6e5604e8e17bd9f108d91e26afe6281dac8fda0091040a7a6d7bd9b43b5",
    "db74c9a30411e00407a50fa346b5e1931a2aa1a35737c709c3fdc21b55a88237",
    "dbc4a04327176e6577b4da46df04564150053960eba5d89587dad1f76a818d80",
    "dd130a849d7b29e5541b05d2f7f86a4acd4f1ec598c1c9438783f56bc4f0ff80",
    "dd56de4137951d9c92681b03416ec15f886b4482a27e3a517d32f085244cbe5d",
    "e0bc60c82713f64ef8a57c0c40d02ce24fd0141d5cc3086259c19b1e62a62bea",
    "e3e93b60bd722ced25a041f65afd4e396e2bafe57e0c3de0c8b6b0aa8b054506",
    "e4ad93ca07acb8d908a3aa41e920ea4f4ef4f26e7f86cf8291c5db289780a5ae",
    "e54fc6b51915e222ba6196747a19ebb8dfa651fd2b46a385a0ded647fbfefda0",
    "e83664255c6963e962bb20f9fcfaad1b570ddf5da69f5444ed37e5260f3ef689",
    "e8f56862d74ef5599af4eeca73924bfa44a6773a497af0c29c48e18729ba6ff0",
    "e9a63a4eb15738ae85cd416221c8fcc4ccc0018fac91335b42eaa016c76e87f9",
    "ed45d626b07112a8a501d9672f3b92796a6754b8d8d9cb4c617fec9774889220",
    "ee79976c9380d5e337fc1c095ece8c8f22f91f306ceeb161fa51fecede2c4ba1",
    "ef51306214d9a6361ee1d5b452e6d2bb70dc7ebb85bf9e02c3d4747fb57d6bec",
    "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f",
    "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7",
    "fbfb386efea67e816f2dda0a8c94a98eb203757aebb3f55f183755a192d44467",
    "fc613b4dfd6736a7bd268c8a0e74ed0d1c04a959f59dd74ef2874983fd443fc9",
];

/// 无 2FA 提示（FR-6.6 / AUD-06，Should 非门禁）：条目 URL 域名在本地
/// 2FA 支持域名白名单中、但条目未配置 TOTP 的条目 id。
///
/// 输入为 `(item_id, url, has_totp)` 对；`url` 为 `None`（无 URL）或域名
/// 不在白名单 → 不报（白名单覆盖范围有限，宁可漏报）。输出保持输入顺序
/// 并去重。
#[must_use]
pub fn find_missing_totp(entries: &[(String, Option<&str>, bool)]) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    for (item_id, url, has_totp) in entries {
        if *has_totp {
            continue;
        }
        let Some(url) = url else {
            continue;
        };
        let Some(host) = url_host(url) else {
            continue;
        };
        if !host_in_whitelist(&host) {
            continue;
        }
        if !hits.iter().any(|seen| seen == item_id) {
            hits.push(item_id.clone());
        }
    }
    hits
}

/// 本地 2FA 支持域名白名单（FR-6.6：覆盖范围有限，仅收录业界公认知名
/// 支持 2FA 的站点主域名；随版本更新，宁缺毋滥）。
const TWO_FA_DOMAINS: [&str; 40] = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "google.com",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "outlook.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "reddit.com",
    "linkedin.com",
    "dropbox.com",
    "box.com",
    "slack.com",
    "discord.com",
    "zoom.us",
    "cloudflare.com",
    "digitalocean.com",
    "heroku.com",
    "vercel.com",
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "atlassian.com",
    "okta.com",
    "paypal.com",
    "stripe.com",
    "proton.me",
    "protonmail.com",
    "notion.so",
    "steamcommunity.com",
    "steampowered.com",
    "playstation.com",
    "nintendo.com",
];

/// 域名是否在白名单中（主域名或其子域名均命中）。
fn host_in_whitelist(host: &str) -> bool {
    TWO_FA_DOMAINS
        .iter()
        .any(|d| host == *d || host.strip_suffix(d).is_some_and(|prefix| prefix.ends_with('.')))
}

/// 从 URL 提取 host（宽松解析，提取失败返回 `None`）：去 scheme →
/// 截断到路径前 → 去userinfo → 去 port → 去多级 `www.` 前缀 → 小写。
fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.split('/').next().unwrap_or(rest);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    // IPv6 字面量（[..]）不在白名单坐标系内，整体放弃
    if rest.starts_with('[') {
        return None;
    }
    let host = rest.split(':').next().unwrap_or(rest);
    let mut host = host.to_ascii_lowercase();
    while let Some(stripped) = host.strip_prefix("www.") {
        host = stripped.to_owned();
    }
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    /// AUD-04：恰好阈值不报、跨过整天数边界即报（措辞为"> 阈值"，
    /// 距今天数按整天向下取整）。
    #[test]
    fn 陈旧密码阈值边界() {
        // updated_at = 1_000_000；now 推进恰好 threshold 天 → 不报
        let entries = vec![("a".to_string(), 1_000_000i64)];
        assert!(find_stale_passwords(&entries, 1_000_000 + 365 * SECS_PER_DAY, 365).is_empty());
        // 累计满 366 个整天 → 366 > 365，报
        assert_eq!(
            find_stale_passwords(&entries, 1_000_000 + 366 * SECS_PER_DAY, 365),
            vec!["a".to_string()]
        );
    }

    /// AUD-04：默认阈值 365 可配置；未来 updated_at 不报；去重保序。
    #[test]
    fn 陈旧密码可配置阈值与去重() {
        let entries = vec![
            ("a".to_string(), 0i64),
            ("b".to_string(), 100i64),
            ("a".to_string(), 0i64),
        ];
        // 阈值 30：a（31 个整天）报，b（30 个整天）不报
        assert_eq!(
            find_stale_passwords(&entries, 31 * SECS_PER_DAY, 30),
            vec!["a".to_string()]
        );
        // 阈值加大到 400：全不报
        assert!(find_stale_passwords(&entries, 31 * SECS_PER_DAY, 400).is_empty());
        // updated_at 在未来（时钟偏移）：不报
        let future = vec![("f".to_string(), 10_000i64)];
        assert!(find_stale_passwords(&future, 0, 365).is_empty());
        // 默认常量冻结
        assert_eq!(DEFAULT_STALE_DAYS, 365);
    }

    /// AUD-05：明文精确命中字典 → High；强随机密码与空串不命中。
    #[test]
    fn 字典精确命中与漏报() {
        let items = vec![
            ("w1".to_string(), "password".to_string()),
            ("w2".to_string(), "123456".to_string()),
            ("s1".to_string(), "xK9#mQ2$vL8pZ4!nR7wT".to_string()),
            ("e1".to_string(), String::new()),
        ];
        let hits = find_common_passwords(&items);
        assert_eq!(hits.len(), 2, "只报字典命中的两条");
        assert_eq!(hits[0].item_id, "w1");
        assert_eq!(hits[0].rule, CommonPasswordRule::DictionaryExact);
        assert_eq!(hits[0].confidence, Confidence::High);
        assert_eq!(hits[1].item_id, "w2");
    }

    /// AUD-05：leet 归一命中 → Medium（dr4g0n → dragon）。
    #[test]
    fn leet归一命中置信度中() {
        let items = vec![("l1".to_string(), "dr4g0n".to_string())];
        let hits = find_common_passwords(&items);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, CommonPasswordRule::LeetNormalized);
        assert_eq!(hits[0].confidence, Confidence::Medium);
    }

    /// AUD-05：p@ssw0rd 本身在字典中 → 精确 High（不做归一降级）。
    #[test]
    fn 字典内leet原词按精确命中() {
        let items = vec![("x".to_string(), "p@ssw0rd".to_string())];
        let hits = find_common_passwords(&items);
        assert_eq!(hits[0].rule, CommonPasswordRule::DictionaryExact);
        assert_eq!(hits[0].confidence, Confidence::High);
    }

    /// AUD-05：8 位生日形态 → Low；月/日越界不报（宁可漏报）。
    #[test]
    fn 生日形态低置信度() {
        let items = vec![
            ("b1".to_string(), "19900115".to_string()),
            ("b2".to_string(), "19901315".to_string()), // 月 13
            ("b3".to_string(), "18991231".to_string()), // 年越界
            ("b4".to_string(), "1990121".to_string()),  // 7 位
        ];
        let hits = find_common_passwords(&items);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].item_id, "b1");
        assert_eq!(hits[0].rule, CommonPasswordRule::BirthdayPattern);
        assert_eq!(hits[0].confidence, Confidence::Low);
    }

    /// AUD-05：键盘行序列 → Low（含序列的长密码也命中）。
    #[test]
    fn 键盘序列低置信度() {
        let items = vec![("k1".to_string(), "MyQwerty!99x".to_string())];
        let hits = find_common_passwords(&items);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, CommonPasswordRule::KeyboardSequence);
        assert_eq!(hits[0].confidence, Confidence::Low);
    }

    /// 每个条目最多一条命中，多段密码取置信度最高者（精确 > leet > 形态）。
    #[test]
    fn 每条目单命中且按优先级() {
        // "password" 精确命中，不得再产出低优先规则
        let items = vec![("a".to_string(), "password".to_string())];
        let hits = find_common_passwords(&items);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, Confidence::High);
        // 同条目两段密码：第一段未命中、第二段精确命中 → 报 High
        let multi = vec![
            ("m".to_string(), "xK9#mQ2$vL8pZ4".to_string()),
            ("m".to_string(), "123456".to_string()),
        ];
        let hits = find_common_passwords(&multi);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].item_id, "m");
        assert_eq!(hits[0].confidence, Confidence::High);
        // 命中顺序颠倒：低置信度在前，仍取高置信度者
        let reversed = multi.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(find_common_passwords(&reversed)[0].confidence, Confidence::High);
    }

    /// AUD-06：白名单域名且无 TOTP → 报；有 TOTP / 无 URL / 白名单外 → 不报。
    #[test]
    fn 无totp提示按白名单() {
        let entries = vec![
            ("a".to_string(), Some("https://github.com/foo"), false),
            ("b".to_string(), Some("https://github.com"), true),
            ("c".to_string(), None, false),
            ("d".to_string(), Some("https://example.org"), false),
            ("e".to_string(), Some("https://mail.google.com/u/0"), false),
        ];
        assert_eq!(
            find_missing_totp(&entries),
            vec!["a".to_string(), "e".to_string()],
            "子域名应命中主域名白名单"
        );
    }

    /// AUD-06：host 提取的宽松解析边界（端口 / userinfo / www / 大小写）。
    #[test]
    fn 无totp提示的host提取边界() {
        let entries = vec![
            ("p1".to_string(), Some("HTTPS://GITHUB.COM:443/x"), false),
            ("p2".to_string(), Some("https://user@www.github.com"), false),
            ("p3".to_string(), Some("github.com"), false),
            ("p4".to_string(), Some("https://notgithub.com"), false),
            ("p5".to_string(), Some("https://[2001:db8::1]/"), false),
        ];
        assert_eq!(
            find_missing_totp(&entries),
            vec!["p1".to_string(), "p2".to_string(), "p3".to_string()],
            "端口/userinfo/www 前缀剥离后命中；notgithub.com 不得尾缀误匹配；IPv6 不在坐标系"
        );
    }

    /// 字典指纹表有序性（二分查找前置条件）与自洽性。
    #[test]
    fn 字典表有序且指纹自洽() {
        for pair in COMMON_PASSWORD_SHA256.windows(2) {
            assert!(pair[0] < pair[1], "字典必须严格升序（二分前置条件）");
        }
        // 表内容自洽：password / 123456 / qwerty 必命中，且表规模在 100–200
        for known in ["password", "123456", "qwerty"] {
            assert!(dict_hit(known), "「{known}」必须在字典中");
        }
        assert!((100..=200).contains(&COMMON_PASSWORD_SHA256.len()));
    }
}
