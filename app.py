"""
Flask Web应用 - 基于AI的钓鱼网站识别与预警系统
包含检测、用户登录、举报提交与后台管理功能
"""
import ipaddress
import os
import socket
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from feature_extractor import CombinedFeatureExtractor, calculate_phishing_score
from model_trainer import PhishingModelTrainer


app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "phishing-detection-graduation-project")
app.config["DATABASE"] = str(Path("app.db"))

# 通过环境变量控制是否允许检测本机或内网地址，便于本地演示和安全部署之间切换。
ALLOW_LOCAL_TESTING = os.getenv("ALLOW_LOCAL_TESTING", "1") == "1"
ALLOW_PRIVATE_NETWORK = os.getenv("ALLOW_PRIVATE_NETWORK", "1") == "1"


# 全局复用特征提取器和模型训练器，避免每次请求都重复初始化对象。
feature_extractor = CombinedFeatureExtractor()
model_trainer = PhishingModelTrainer()


def get_db():
    """获取数据库连接"""
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库和默认管理员"""
    db = get_db()
    # 首次运行时自动建表，系统因此可以直接启动，不需要手工导入数据库结构。
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            probability REAL NOT NULL,
            risk_level TEXT NOT NULL,
            risk_factors TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            reported_url TEXT NOT NULL,
            description TEXT NOT NULL,
            contact TEXT,
            status TEXT NOT NULL DEFAULT '待处理',
            ai_is_phishing INTEGER NOT NULL,
            ai_probability REAL NOT NULL,
            ai_risk_level TEXT NOT NULL,
            ai_risk_factors TEXT NOT NULL,
            review_note TEXT,
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )

    admin = db.execute("SELECT id FROM users WHERE username = 'admin' LIMIT 1").fetchone()
    if admin is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (
                "admin",
                generate_password_hash("admin123456"),
                "admin",
                _now_str(),
            ),
        )
    db.commit()


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@app.before_request
def load_logged_in_user():
    init_db()
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "SELECT id, username, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("请先登录后再继续操作。", "warning")
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("请先登录管理员账号。", "warning")
            return redirect(url_for("login", next=request.path))
        if g.user["role"] != "admin":
            flash("你没有访问后台的权限。", "danger")
            return redirect(url_for("index"))
        return view(**kwargs)

    return wrapped_view


def load_best_model():
    """自动检测并加载模型"""
    model_dir = Path("models")
    # 按模型效果和部署偏好设置加载顺序，优先使用训练阶段保存的最优模型。
    model_priority = [
        "ensemble",
        "random_forest",
        "gradient_boosting",
        "logistic_regression",
        "svm",
        "mlp",
    ]

    for model_name in model_priority:
        model_path = model_dir / f"{model_name}.pkl"
        scaler_path = model_dir / f"{model_name}_scaler.pkl"
        if not model_path.exists():
            continue

        try:
            model_trainer.best_model = joblib.load(model_path)
            model_trainer.best_model_name = model_name
            if scaler_path.exists():
                model_trainer.scaler = joblib.load(scaler_path)
            print(f"模型已加载: {model_name}")
            return
        except Exception as exc:
            print(f"加载模型 {model_name} 时出错: {exc}")

    model_files = [f for f in model_dir.glob("*.pkl") if "_scaler" not in f.name]
    for model_path in model_files:
        try:
            model_name = model_path.stem
            model_trainer.best_model = joblib.load(model_path)
            model_trainer.best_model_name = model_name
            scaler_path = model_dir / f"{model_name}_scaler.pkl"
            if scaler_path.exists():
                model_trainer.scaler = joblib.load(scaler_path)
            print(f"模型已加载: {model_name}")
            return
        except Exception as exc:
            print(f"加载模型 {model_path.name} 时出错: {exc}")

    print("警告: 未找到可用的模型文件，请先运行 python train.py 训练模型")
    print("   将使用基于规则的检测方法")


def validate_target_url(url):
    """URL校验与SSRF防护"""
    # 统一补全协议，并限制只允许 http/https，避免用户输入 file:// 等危险协议。
    normalized_url = url if url.startswith(("http://", "https://")) else "https://" + url
    parsed_url = urlparse(normalized_url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError("仅支持http/https协议")

    host = parsed_url.netloc.split(":")[0].lower()
    try:
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            try:
                resolved_ip = socket.gethostbyname(host)
                ip_obj = ipaddress.ip_address(resolved_ip)
            except Exception:
                ip_obj = None

        if ip_obj and (
            (ip_obj.is_private and not ALLOW_PRIVATE_NETWORK)
            or ip_obj.is_reserved
            or ip_obj.is_link_local
            or (ip_obj.is_loopback and not ALLOW_LOCAL_TESTING)
        ):
            raise ValueError("目标地址不允许（内网/环回）")
    except ValueError:
        raise
    except Exception:
        pass

    return normalized_url


def _risk_level(probability):
    if probability >= 0.7:
        return "高风险"
    if probability >= 0.4:
        return "中风险"
    return "低风险"


def _is_local_address(domain):
    try:
        if domain in ["localhost", "127.0.0.1", "::1"]:
            return True
        try:
            ip_obj = ipaddress.ip_address(domain)
            return ip_obj.is_loopback or ip_obj.is_private
        except ValueError:
            try:
                resolved_ip = socket.gethostbyname(domain)
                ip_obj = ipaddress.ip_address(resolved_ip)
                return ip_obj.is_loopback or ip_obj.is_private
            except Exception:
                return False
    except Exception:
        return False


def _trusted_domain(domain):
    trusted_domains = [
        "github.com",
        "google.com",
        "microsoft.com",
        "apple.com",
        "baidu.com",
        "qq.com",
        "taobao.com",
        "alipay.com",
        "amazon.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "stackoverflow.com",
        "wikipedia.org",
        "youtube.com",
    ]
    for trusted_domain in trusted_domains:
        if (
            domain == trusted_domain
            or domain == f"www.{trusted_domain}"
            or domain.endswith(f".{trusted_domain}")
        ):
            return True
    return False


def _store_detection(user_id, url, is_phishing, probability, risk_level, risk_factors):
    # 将每次检测结果持久化，供首页最近记录和后台统计使用。
    get_db().execute(
        """
        INSERT INTO detections (user_id, url, is_phishing, probability, risk_level, risk_factors, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            url,
            int(bool(is_phishing)),
            float(probability),
            risk_level,
            "\n".join(risk_factors),
            _now_str(),
        ),
    )
    get_db().commit()


def perform_detection(url, user_id=None, save_record=True):
    """执行检测并返回结果"""
    # 检测主流程：URL校验 -> 特征提取 -> 模型预测/规则兜底 -> 风险解释 -> 保存记录。
    normalized_url = validate_target_url(url.strip())
    features = feature_extractor.extract_all_features(normalized_url)

    print("\n=== 特征提取结果 ===")
    print(f"URL: {normalized_url}")
    print(f"status_code: {features.get('status_code', 0)}")
    print(f"content_length: {features.get('content_length', 0)}")
    print(f"iframe_count: {features.get('iframe_count', 0)}")
    print(f"IframeOrFrame: {features.get('IframeOrFrame', 0)}")
    print(f"form_count: {features.get('form_count', 0)}")
    print(f"suspicious_forms: {features.get('suspicious_forms', 0)}")
    print(f"popup_count: {features.get('popup_count', 0)}")
    print(f"PopUpWindow: {features.get('PopUpWindow', 0)}")
    print(f"Redirect: {features.get('Redirect', 0)}")
    print("===================\n")

    webpage_features_failed = features.get("status_code", 0) == 0 and features.get("content_length", 0) == 0
    if webpage_features_failed:
        print("警告：网页特征提取失败，仅使用URL特征进行检测")

    if model_trainer.best_model is None:
        # 没有模型文件时使用规则评分兜底，保证系统仍可演示和运行。
        probability = calculate_phishing_score(features)
        is_phishing = probability >= 0.5
    else:
        try:
            models_need_scaler = ["logistic_regression", "svm", "mlp"]
            use_scaler = model_trainer.best_model_name in models_need_scaler and hasattr(model_trainer.scaler, "transform")

            # 只保留数值特征，并按训练时模型记录的特征名对齐，避免训练/预测列顺序不一致。
            numeric_features = {k: v for k, v in features.items() if isinstance(v, (int, float))}
            feature_df_numeric = pd.DataFrame([numeric_features])

            if hasattr(model_trainer.best_model, "feature_names_in_"):
                expected_features = list(model_trainer.best_model.feature_names_in_)
                feature_df_numeric = feature_df_numeric.reindex(columns=expected_features, fill_value=0)
            elif hasattr(model_trainer.best_model, "n_features_in_"):
                n_features = model_trainer.best_model.n_features_in_
                if len(feature_df_numeric.columns) < n_features:
                    for index in range(len(feature_df_numeric.columns), n_features):
                        feature_df_numeric[f"pad_{index}"] = 0
                elif len(feature_df_numeric.columns) > n_features:
                    feature_df_numeric = feature_df_numeric.iloc[:, :n_features]

            feature_input = model_trainer.scaler.transform(feature_df_numeric) if use_scaler else feature_df_numeric

            if hasattr(model_trainer.best_model, "n_features_in_") and feature_input.shape[1] != model_trainer.best_model.n_features_in_:
                raise ValueError(
                    f"特征数量不匹配: {feature_input.shape[1]} vs {model_trainer.best_model.n_features_in_}"
                )

            prediction = model_trainer.best_model.predict(feature_input)[0]
            probability = model_trainer.best_model.predict_proba(feature_input)[0][1]
            is_phishing = prediction == 1
            print(f"模型预测成功: {'钓鱼网站' if is_phishing else '正常网站'}, 概率: {probability:.2%}")
        except Exception as exc:
            print(f"模型预测出错: {exc}")
            probability = calculate_phishing_score(features)
            is_phishing = probability >= 0.5
            print(f"使用规则判断，评分: {probability:.2%}")

    parsed_url = urlparse(normalized_url)
    domain = parsed_url.netloc.lower().split(":")[0]
    is_trusted = _trusted_domain(domain)

    if is_trusted:
        # 对常见可信域名降低风险，减少知名网站被复杂URL误判的情况。
        probability = min(probability, 0.2)
        is_phishing = False
        print("检测到知名网站，降低风险评分")

    risk_factors = _analyze_risk_factors(features, webpage_features_failed)
    is_local = _is_local_address(domain)

    if not is_trusted and len(risk_factors) > 3 and probability < 0.5:
        rule_score = calculate_phishing_score(features)
        if rule_score > probability:
            probability = rule_score
            is_phishing = rule_score >= 0.5

    if not is_trusted:
        # 将多个高危现象组合起来二次校准风险，弥补模型在单个样本上的保守判断。
        high_risk_combinations = [
            "未使用HTTPS协议" in risk_factors and "包含iframe" in risk_factors and "表单包含敏感字段" in risk_factors,
            "未使用HTTPS协议" in risk_factors and "表单包含敏感字段" in risk_factors and "包含弹窗脚本" in risk_factors,
            "包含iframe" in risk_factors and "表单包含敏感字段" in risk_factors,
        ]

        if any(high_risk_combinations):
            probability = max(probability, 0.7)
            is_phishing = True
        elif "未使用HTTPS协议" in risk_factors and "SSL证书无效" in risk_factors:
            other_risk_factors = [f for f in risk_factors if f not in ["未使用HTTPS协议", "SSL证书无效"]]
            if len(other_risk_factors) >= 2 and not is_local and probability < 0.7:
                probability = max(probability, 0.7)
                is_phishing = True
            elif len(other_risk_factors) >= 1 and probability < 0.4:
                probability = max(probability, 0.4)
            elif not is_local and probability < 0.3:
                probability = max(probability, 0.3)
            elif is_local and probability < 0.4:
                probability = max(probability, 0.4)
        elif is_local and "未使用HTTPS协议" in risk_factors and "SSL证书无效" in risk_factors and probability < 0.4:
            probability = max(probability, 0.4)
        elif len(risk_factors) >= 4:
            if probability < 0.5:
                probability = max(probability, 0.5)
                is_phishing = True
            if len(risk_factors) >= 5 and probability < 0.7:
                probability = max(probability, 0.7)
                is_phishing = True

    risk_level = _risk_level(probability)
    result = {
        "success": True,
        "url": normalized_url,
        "is_phishing": bool(is_phishing),
        "probability": float(probability),
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "features": {
            k: float(v) if isinstance(v, (int, float, np.number)) else str(v)
            for k, v in features.items()
        },
    }

    if save_record:
        _store_detection(user_id, normalized_url, is_phishing, probability, risk_level, risk_factors)

    return result


@app.route("/")
def index():
    recent_detections = []
    if g.user is not None:
        recent_detections = get_db().execute(
            """
            SELECT url, risk_level, probability, created_at
            FROM detections
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 5
            """,
            (g.user["id"],),
        ).fetchall()
    return render_template("index.html", recent_detections=recent_detections)


@app.route("/api/detect", methods=["POST"])
def detect():
    # 前端首页通过这个JSON接口提交URL并接收检测结果。
    try:
        data = request.get_json() or {}
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"success": False, "error": "URL不能为空"}), 400

        result = perform_detection(url, user_id=g.user["id"] if g.user else None, save_record=True)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("用户名和密码不能为空。", "danger")
        elif len(username) < 3:
            flash("用户名至少需要 3 个字符。", "danger")
        elif len(password) < 6:
            flash("密码至少需要 6 位。", "danger")
        elif password != confirm_password:
            flash("两次输入的密码不一致。", "danger")
        else:
            db = get_db()
            existing_user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing_user is not None:
                flash("该用户名已存在，请更换。", "danger")
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'user', ?)",
                    (username, generate_password_hash(password), _now_str()),
                )
                db.commit()
                flash("注册成功，请登录。", "success")
                return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("用户名或密码错误。", "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash("登录成功。", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("你已退出登录。", "success")
    return redirect(url_for("index"))


@app.route("/report", methods=["GET", "POST"])
@login_required
def report_site():
    detection_result = None
    if request.method == "POST":
        # 举报时先自动完成一次AI检测，再把检测结论和用户描述一起存入举报表。
        reported_url = request.form.get("reported_url", "").strip()
        description = request.form.get("description", "").strip()
        contact = request.form.get("contact", "").strip()

        if not reported_url or not description:
            flash("举报网址和举报说明不能为空。", "danger")
        else:
            try:
                detection_result = perform_detection(reported_url, user_id=g.user["id"], save_record=True)
                get_db().execute(
                    """
                    INSERT INTO reports (
                        user_id, reported_url, description, contact, status,
                        ai_is_phishing, ai_probability, ai_risk_level, ai_risk_factors,
                        review_note, created_at, reviewed_at
                    ) VALUES (?, ?, ?, ?, '待处理', ?, ?, ?, ?, '', ?, NULL)
                    """,
                    (
                        g.user["id"],
                        detection_result["url"],
                        description,
                        contact,
                        int(detection_result["is_phishing"]),
                        detection_result["probability"],
                        detection_result["risk_level"],
                        "\n".join(detection_result["risk_factors"]),
                        _now_str(),
                    ),
                )
                get_db().commit()
                flash("举报已提交，系统已自动完成AI检测。", "success")
                return redirect(url_for("my_reports"))
            except ValueError as exc:
                flash(str(exc), "danger")
            except Exception as exc:
                flash(f"举报提交失败：{exc}", "danger")

    return render_template("report.html", detection_result=detection_result, preset_url=request.args.get("url", ""))


@app.route("/my-reports")
@login_required
def my_reports():
    reports = get_db().execute(
        """
        SELECT id, reported_url, description, contact, status, ai_probability,
               ai_risk_level, ai_risk_factors, review_note, created_at, reviewed_at
        FROM reports
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (g.user["id"],),
    ).fetchall()
    return render_template("my_reports.html", reports=reports)


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        "user_count": db.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'user'").fetchone()["count"],
        "report_count": db.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"],
        "pending_report_count": db.execute("SELECT COUNT(*) AS count FROM reports WHERE status = '待处理'").fetchone()["count"],
        "detection_count": db.execute("SELECT COUNT(*) AS count FROM detections").fetchone()["count"],
    }
    latest_reports = db.execute(
        """
        SELECT reports.id, users.username, reports.reported_url, reports.status,
               reports.ai_risk_level, reports.created_at
        FROM reports
        JOIN users ON users.id = reports.user_id
        ORDER BY reports.id DESC
        LIMIT 8
        """
    ).fetchall()
    latest_detections = db.execute(
        """
        SELECT detections.url, detections.risk_level, detections.probability,
               detections.created_at, users.username
        FROM detections
        LEFT JOIN users ON users.id = detections.user_id
        ORDER BY detections.id DESC
        LIMIT 8
        """
    ).fetchall()
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        latest_reports=latest_reports,
        latest_detections=latest_detections,
    )


@app.route("/admin/reports")
@admin_required
def admin_reports():
    reports = get_db().execute(
        """
        SELECT reports.*, users.username
        FROM reports
        JOIN users ON users.id = reports.user_id
        ORDER BY reports.id DESC
        """
    ).fetchall()
    return render_template("admin_reports.html", reports=reports)


@app.route("/admin/reports/<int:report_id>/review", methods=["POST"])
@admin_required
def review_report(report_id):
    status = request.form.get("status", "待处理").strip()
    review_note = request.form.get("review_note", "").strip()
    allowed_statuses = {"待处理", "已确认钓鱼", "误报", "已处置"}
    if status not in allowed_statuses:
        flash("无效的举报状态。", "danger")
        return redirect(url_for("admin_reports"))

    get_db().execute(
        "UPDATE reports SET status = ?, review_note = ?, reviewed_at = ? WHERE id = ?",
        (status, review_note, _now_str(), report_id),
    )
    get_db().commit()
    flash("举报审核结果已更新。", "success")
    return redirect(url_for("admin_reports"))


def _analyze_risk_factors(features, webpage_features_failed=False):
    """分析风险因素"""
    # 把模型特征转换成用户能读懂的风险说明，提升结果可解释性。
    factors = []

    if webpage_features_failed:
        factors.append("网页特征提取失败（可能网站无法访问）")
    if features.get("has_ip", 0) == 1:
        factors.append("URL包含IP地址")
    if features.get("has_at_symbol", 0) == 1:
        factors.append("URL包含@符号")
    if features.get("url_length", 0) > 100:
        factors.append("URL长度异常")
    if features.get("suspicious_keywords", 0) > 1:
        factors.append("包含可疑关键词")
    if features.get("https_used", 0) == 0:
        factors.append("未使用HTTPS协议")
    if features.get("ssl_cert_valid", 0) == 0:
        factors.append("SSL证书无效")
    if features.get("iframe_count", 0) > 0:
        factors.append("包含iframe")

    popup_count = features.get("popup_count", 0)
    if popup_count > 0:
        if features.get("suspicious_forms", 0) > 0 or features.get("iframe_count", 0) > 0:
            factors.append("包含弹窗脚本")
        elif popup_count > 2:
            factors.append("包含多个弹窗脚本")

    if features.get("suspicious_forms", 0) > 0:
        factors.append("表单包含敏感字段")
    elif features.get("form_count", 0) > 3:
        factors.append("包含多个表单")

    domain_age = features.get("domain_age_days", 0)
    if domain_age > 0 and domain_age < 90:
        factors.append("域名注册时间很短（小于90天）")
    if features.get("meta_refresh", 0) == 1:
        factors.append("包含自动刷新/重定向")
    if features.get("script_count", 0) > 10:
        factors.append("包含大量脚本")
    if not factors:
        factors.append("未发现明显风险因素")
    return factors


load_best_model()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
