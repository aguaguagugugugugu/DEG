from flask import Flask, send_from_directory, jsonify, request,render_template,redirect,session,url_for
import uuid
import hmac
import os
from datetime import datetime
import bcrypt
import requests
import threading
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
candidates_store = []
votes_store = []
codes   = {"1111111111111111"}   # set вместо list — O(1) и атомарный discard
verifd  = set()                  # set вместо list
seen_requests = set()
# ─── Секретный токен для админ-операций ───
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
TURNSTILE_SECRET = os.environ.get("SECRET")
print(TURNSTILE_SECRET)
TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
# ═══════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНОЕ — проверка админ-токена
# ═══════════════════════════════════════════════════
def check_admin():
    token = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(token, ADMIN_TOKEN):
        return False
    return True


def get_country(ip):
    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
    if r.json()['status'] == 'fail':
        return 'RU'
    return r.json()['countryCode']
# ═══════════════════════════════════════════════════
#  ГЛАВНАЯ СТРАНИЦА
# ═══════════════════════════════════════════════════
@limiter.limit("60 per minute") 
@app.route('/vote')
def index():
    if session.get('hash') in verifd:
      if get_country(get_ip()) == 'RU':
        return render_template('index.html')
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

    # ─── 1. Валидация входа ───
    if not request_id or not candidate_id:
        return jsonify(error="request_id и candidate_id обязательны"), 400

    h = session.get('hash')
    if not h:
        return jsonify(error="Не верифицирован"), 403

    # ─── 2. Вся логика голоса — под одним локом ───
    with _lock:

        # 2.1. Идемпотентность: этот request_id уже голосовал?
        if any(v['request_id'] == request_id for v in votes_store):
            return jsonify(status="duplicate", request_id=request_id), 409

        # 2.2. Кандидат существует?
        candidate = next((c for c in candidates_store if c['id'] == candidate_id), None)
        if not candidate:
            return jsonify(error="candidate not found"), 404

        # 2.3. Право голоса ещё есть?
        if h not in verifd:
            return jsonify(error="Вы уже голосовали"), 409

        # 2.4. Атомарно съедаем право голоса
        verifd.discard(h)

        # 2.5. Записываем голос
        candidate['votes'] += 1
        votes_store.append({
            "request_id":   request_id,
            "candidate_id": candidate_id,
            "ts":           datetime.now(timezone.utc).isoformat(),
            "ip":           request.remote_addr,
        })

    # ─── 3. Ротация сессии ───
    session.clear()

    return jsonify(
        status="accepted",
        request_id=request_id,
        vote_id=str(uuid.uuid4()),
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
    if get_country(get_ip()) == 'RU':
        return render_template('vxod.html')
    else:
        return redirect(url_for('block'))
@limiter.limit("60 per minute")
@app.route('/api/check',methods=['POST'])
def che ():
    data = request.get_json() or {}
    token = data.get('turnstile', '')
    code = data.get ('code')
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
# ═══════════════════════════════════════════════════
#  ЗАПУСК
# ═══════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
