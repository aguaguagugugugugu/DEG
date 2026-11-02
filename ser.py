from flask import Flask, send_from_directory, jsonify, request,render_template,redirect,session,url_for
import uuid
import hmac
import os
from datetime import datetime,timezone,timedelta
import bcrypt
import requests
import threading
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
_lock = threading.Lock()
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.urandom(32)   
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=900,     # 15 минут
)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],           # общий лимит >
    storage_uri="memory://",                    # для одного >
)
def get_ip():
    return request.remote_addr
# ─── Хранилище в памяти (для теста; в проде — БД) ───
_ip_cache = {}          # ip → (timestamp, info)
IP_TTL = timedelta(hours=1)
candidates_store = []
votes_store = []
annulled_votes = set()
codes   = {"1111111111111111"}   # set вместо list — O(1) и атомарный discard
verifd  = set()                  # set вместо list
seen_requests = set()
# ─── Секретный токен для админ-операций ───
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMPASS")
TURNSTILE_SECRET = os.environ.get("SECRET")
print(repr(TURNSTILE_SECRET))
TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
# ═══════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНОЕ — проверка админ-токена
# ═══════════════════════════════════════════════════
def check_admin():
    token = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(token, ADMIN_TOKEN):
        return False
    return True

def compute_fraud_score(vote: dict, ip_info: dict | None) -> tuple[int, list[str]]:
    """Считает подозрительность голоса 0..100 и возвращает причины."""
    score = 0
    reasons = []

    ip = vote.get('ip', '')
    ua = vote.get('user_agent', '')

    # 1. IP не из РФ
    if ip_info:
        cc = ip_info.get('countryCode', '')
        if cc and cc != 'RU':
            score += 40
            reasons.append(f"IP из другой страны ({cc})")

        if ip_info.get('hosting'):
            score += 40
            reasons.append("Датацентр/хостинг")

        if ip_info.get('proxy'):
            score += 40
            reasons.append("Прокси/VPN")

        if ip_info.get('mobile'):
            reasons.append("Мобильный интернет")

    # 2. Подозрительный User-Agent
    if not ua or 'Mozilla' not in ua:
        score += 50
        reasons.append("UA не похож на браузер")

    bad = ['curl', 'wget', 'python', 'headless', 'phantom', 'selenium']
    if any(b in ua.lower() for b in bad):
        score += 40
        reasons.append("UA содержит признаки автоматизации")

    # 3. Частота IP
    ip_count = sum(1 for v in votes_store if v.get('ip') == ip and not v.get('invalid'))
    if ip_count >= 10:
        score += 30
        reasons.append(f"Много голосов с одного IP ({ip_count})")
    elif ip_count >= 3:
        score += 10

    return min(score, 100), reasons


def get_country(ip: str) -> dict:
    now = datetime.now()

    # 1. Проверяем кеш
    cached = _ip_cache.get(ip)
    if cached and now - cached[0] < IP_TTL:
        return cached[1]        # ← вернули из памяти, не дёрнули API

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={'fields': 'status,countryCode,country,hosting,proxy,mobile'},
            timeout=3
        )
        data = r.json()
        info = data if data.get('status') == 'success' else {'countryCode': 'RU', 'hosting': False, 'proxy': False}
    except Exception:
        info = {}
    print(info)
    # 4. Запоминаем на час
    _ip_cache[ip] = (now, info)
    return info
# ═══════════════════════════════════════════════════
#  ГЛАВНАЯ СТРАНИЦА
# ═══════════════════════════════════════════════════
def get_csrf_token() -> str:
    """Возвращает CSRF-токен сессии (создаёт при первом вызове)."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def check_csrf() -> bool:
    """Проверяет CSRF-токен из заголовка X-CSRF-Token."""
    expected = session.get('csrf_token')
    if not expected:
        return False
    provided = request.headers.get('X-CSRF-Token', '')
    return hmac.compare_digest(provided, expected)
@limiter.limit("60 per minute") 
@app.route('/vote')
def index():
    if session.get('hash') in verifd:
      if get_country(get_ip())['countryCode'] == 'RU':
        return render_template('index.html',csrf=get_csrf_token())
      else:
        return redirect(url_for('block'))
    else:
      return jsonify(error="Forbidden"), 403

# ═══════════════════════════════════════════════════
#  GET /api/candidates — список кандидатов
# ═══════════════════════════════════════════════════
@limiter.limit("60 per minute")
@app.route('/api/candidates', methods=['GET'])
def get_candidates():
    return jsonify(candidates_store)


# ═══════════════════════════════════════════════════
#  POST /api/candidates — добавить кандидата
#  Заголовок: X-Admin-Token
#  Body: {"name": "...", "party": "...", "program": "...", "photo": "..."}
# ═══════════════════════════════════════════════════
@limiter.limit("60 per minute")
@app.route('/api/candidates', methods=['POST'])
def add_candidate():
    if not check_admin():
        return jsonify(error="Forbidden"), 403

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify(error="name required"), 400

    candidate = {
        "id": str(uuid.uuid4()),
        "name": name,
        "party": data.get("party", ""),
        "program": data.get("program", ""),
        "photo": data.get("photo", ""),
        "votes": 0
    }
    candidates_store.append(candidate)
    return jsonify(candidate), 201


# ═══════════════════════════════════════════════════
#  POST /api/vote — обычный голос от избирателя
#  Body: {"request_id": "...", "candidate_id": "..."}
# ═══════════════════════════════════════════════════
@limiter.limit("60 per minute")
@app.route('/api/vote', methods=['POST'])
def vote():
    data = request.get_json() or {}
    request_id   = data.get('request_id')
    candidate_id = data.get('candidate_id')

    # ─── 1. CSRF ───
    if not check_csrf():
        return jsonify(error="Неверный CSRF-токен"), 403

    # ─── 2. Валидация входа ───
    if not request_id or not candidate_id:
        return jsonify(error="request_id и candidate_id обязательны"), 400

    h = session.get('hash')
    if not h:
        return jsonify(error="Не верифицирован"), 403

    # ─── 3. Вся логика — под одним локом ───
    with _lock:
        # 3.1. Только из РФ
        ip = get_ip()
        if get_country(ip).get('countryCode') != 'RU':
            return jsonify(error="Голосование доступно только из РФ"), 403

        # 3.2. Идемпотентность по request_id
        if any(v['request_id'] == request_id for v in votes_store):
            return jsonify(status="duplicate", request_id=request_id), 409

        # 3.3. Право голоса ещё есть?
        if h not in verifd:
            return jsonify(error="Вы уже голосовали"), 409

        # 3.4. Кандидат существует?
        candidate = next((c for c in candidates_store if c['id'] == candidate_id), None)
        if not candidate:
            return jsonify(error="candidate not found"), 404

        # 3.5. Атомарно съедаем право голоса
        verifd.discard(h)

        # 3.6. Считаем fraud score
        ua = request.headers.get('User-Agent', '')
        fp = data.get('fingerprint', '')
        ip_info = get_country(ip)

        vote_doc = {
            "vote_id":      str(uuid.uuid4()),
            "request_id":   request_id,
            "candidate_id": candidate_id,
            "code_hash":    h,
            "ip":           ip,
            "user_agent":   ua,
            "fingerprint":  fp,
            "ts":           datetime.now(timezone.utc).isoformat(),
            "invalid":      False,
        }

        score, reasons = compute_fraud_score(vote_doc, ip_info)
        vote_doc['fraud_score'] = score
        vote_doc['reasons']     = reasons
        vote_doc['suspicious']  = score >= 70

        # 3.7. Записываем ОДИН раз
        votes_store.append(vote_doc)
        candidate['votes'] += 1

        vote_id = vote_doc['vote_id']

    # ─── 4. Ротация сессии ───
    session.clear()

    return jsonify(
        status="accepted",
        request_id=request_id,
        vote_id=vote_id,
    ), 201

@limiter.limit("60 per minute")
@app.route('/api/admin/boost', methods=['POST'])
def boost_votes():
    if not check_admin():
        return jsonify(error="Forbidden"), 403

    data = request.get_json() or {}
    candidate_id = data.get('candidate_id')
    count = data.get('count', 0)

    # Валидация count
    if not isinstance(count, int) or count <= 0:
        return jsonify(error="count должен быть положительным целым числом"), 400

    if count > 1_000_000:
        return jsonify(error="count слишком большой (макс. 1 000 000)"), 400

    # Режим 1: накрутить одному кандидату
    if candidate_id:
        candidate = next((c for c in candidates_store if c['id'] == candidate_id), None)
        if not candidate:
            return jsonify(error="candidate not found"), 404

        candidate['votes'] += count

        return jsonify(
            status="boosted",
            candidate_id=candidate_id,
            candidate_name=candidate['name'],
            added=count,
            total=candidate['votes'],
            ts=datetime.utcnow().isoformat()
        ), 200

    # Режим 2: накрутить всем кандидатам
    if not candidates_store:
        return jsonify(error="нет кандидатов"), 400

    for c in candidates_store:
        c['votes'] += count

    return jsonify(
        status="boosted_all",
        candidates_count=len(candidates_store),
        added_per_candidate=count,
        ts=datetime.utcnow().isoformat()
    ), 200


# ═══════════════════════════════════════════════════
#  POST /api/admin/reset — сбросить голоса
#  Заголовок: X-Admin-Token
#  Body: {"candidate_id": "..."}  либо пусто (сброс всем)
# ═══════════════════════════════════════════════════
@limiter.limit("60 per minute")
@app.route('/api/admin/reset', methods=['POST'])
def reset_votes():
    if not check_admin():
        return jsonify(error="Forbidden"), 403

    data = request.get_json() or {}
    candidate_id = data.get('candidate_id')

    if candidate_id:
        candidate = next((c for c in candidates_store if c['id'] == candidate_id), None)
        if not candidate:
            return jsonify(error="candidate not found"), 404
        candidate['votes'] = 0
        return jsonify(status="reset", candidate_id=candidate_id), 200

    for c in candidates_store:
        c['votes'] = 0
    return jsonify(status="reset_all"), 200

@app.route('/', methods=['POST','GET'])
def vx ():
    if get_country(get_ip())['countryCode'] == 'RU':
        return render_template('vxod.html',csrf=get_csrf_token())
    else:
        return redirect(url_for('block'))
@limiter.limit("60 per minute")
@app.route('/api/check',methods=['POST'])
def che ():
    data = request.get_json() or {}
    token = data.get('turnstile', '')
    code = data.get ('code')
    if not check_csrf():
        return jsonify(error="Неверный CSRF-токен"), 403
    if not token:
        return jsonify(error="Капча не пройдена"), 400

    try:
        r = requests.post(TURNSTILE_URL, data={
            'secret': TURNSTILE_SECRET,
            'response': token,
            'remoteip': request.remote_addr,
        }, timeout=5)
        result = r.json()
    except Exception as e:
        return jsonify(error=f"Ошибка соединения с Cloudflare: {e}"), 500
    print(r.json())
    if not result.get('success'):
        return jsonify(
            error="Капча не прошла проверку",
            codes=result.get('error-codes', [])
        ), 400

    # Атомарно съедаем код — ДО bcrypt
    try:
        codes.remove(code)
    except KeyError:
        return jsonify(error="Ты уже проголосовал!"), 403

    # Теперь bcrypt можно делать сколько угодно долго
    ssi = bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()
    verifd.add(ssi)
    session['hash'] = ssi
    return jsonify(success=True, redirect="/vote")
@limiter.limit("60 per minute")
@app.route('/block')
def block():
  return render_template('block.html')

@app.route('/admin')
def admin_page():
    if not session.get('admin'):
        return render_template('admin_login.html')
    return render_template('admin.html')


@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_login():
    data = request.get_json() or {}
    password = data.get('password', '')

    if not password:
        return jsonify(error="Введите пароль"), 400

    if not bcrypt.checkpw(password.encode(), ADMIN_PASSWORD.encode()):
        return jsonify(error="Неверный пароль"), 401

    session['admin'] = True
    session.permanent = True
    return jsonify(success=True, redirect='/admin')

# ─── Список голосов ───
@app.route('/api/admin/votes', methods=['GET'])
def admin_votes():
    only_suspicious = request.args.get('suspicious') == '1'
    only_active     = request.args.get('active') == '1'
    min_score       = int(request.args.get('min_score', 0))
    candidate_id    = request.args.get('candidate_id', '')
    limit           = min(int(request.args.get('limit', 500)), 2000)

    result = votes_store

    if only_suspicious:
        result = [v for v in result if v.get('suspicious')]
    if only_active:
        result = [v for v in result if not v.get('invalid')]
    if min_score:
        result = [v for v in result if v.get('fraud_score', 0) >= min_score]
    if candidate_id:
        result = [v for v in result if v.get('candidate_id') == candidate_id]

    # Сортировка: сначала подозрительные, потом свежие
    result = sorted(
        result,
        key=lambda v: (v.get('fraud_score', 0), v.get('ts', '')),
        reverse=True
    )[:limit]

    return jsonify({
        "total":            len(votes_store),
        "suspicious_count": sum(1 for v in votes_store if v.get('suspicious')),
        "invalid_count":    sum(1 for v in votes_store if v.get('invalid')),
        "returned":         len(result),
        "votes":            result,
    })


# ─── Аннулировать один голос ───
@app.route('/api/admin/votes/<vote_id>/invalidate', methods=['POST'])

def invalidate_vote(vote_id):
    with _lock:
        vote = next((v for v in votes_store if v['vote_id'] == vote_id), None)
        if not vote:
            return jsonify(error="vote not found"), 404
        if vote.get('invalid'):
            return jsonify(status="already_invalid"), 200

        vote['invalid'] = True

        cand = next((c for c in candidates_store if c['id'] == vote['candidate_id']), None)
        if cand:
            cand['votes'] = max(0, cand['votes'] - 1)

    return jsonify(status="invalidated", vote_id=vote_id), 200


# ─── Массово аннулировать подозрительные ───
@app.route('/api/admin/votes/invalidate-suspicious', methods=['POST'])

def invalidate_all_suspicious():
    data = request.get_json() or {}
    min_score = int(data.get('min_score', 70))

    count = 0
    with _lock:
        for v in votes_store:
            if v.get('invalid'): continue
            if v.get('fraud_score', 0) < min_score: continue

            v['invalid'] = True
            count += 1
            cand = next((c for c in candidates_store if c['id'] == v['candidate_id']), None)
            if cand:
                cand['votes'] = max(0, cand['votes'] - 1)

    return jsonify(status="ok", invalidated=count, min_score=min_score), 200


# ─── Статистика ───
@app.route('/api/admin/stats', methods=['GET'])

def admin_stats():
    scores = [v.get('fraud_score', 0) for v in votes_store]
    return jsonify({
        "votes_total":    len(votes_store),
        "votes_active":   sum(1 for v in votes_store if not v.get('invalid')),
        "votes_invalid":  sum(1 for v in votes_store if v.get('invalid')),
        "suspicious":     sum(1 for v in votes_store if v.get('suspicious')),
        "avg_score":      round(sum(scores)/len(scores), 1) if scores else 0,
        "max_score":      max(scores) if scores else 0,
    })



# ═══════════════════════════════════════════════════
#  ЗАПУСК
# ═══════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
