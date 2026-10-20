# API para cambiar estado y tiempo de habitación
import os
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
from psycopg2.extras import RealDictCursor


# =====================================================================
# SEGURIDAD: Carga de variables de entorno desde un archivo .env
# ---------------------------------------------------------------------
# Las credenciales (clave secreta, contraseña de la BD) ya NO van escritas
# en el código. Se leen de variables de entorno. Para desarrollo local se
# pueden poner en un archivo .env (que está en .gitignore y nunca se sube
# a GitHub). Este cargador es mínimo para no agregar dependencias nuevas.
# Las variables que ya existan en el sistema tienen prioridad sobre el .env.
# =====================================================================
def cargar_env(ruta=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')):
    if not os.path.exists(ruta):
        return
    with open(ruta, encoding='utf-8') as archivo:
        for linea in archivo:
            linea = linea.strip()
            if not linea or linea.startswith('#') or '=' not in linea:
                continue
            clave, valor = linea.split('=', 1)
            os.environ.setdefault(clave.strip(), valor.strip().strip('"').strip("'"))

cargar_env()

# SEGURIDAD: el modo debug solo se activa explícitamente (FLASK_DEBUG=1).
# Con debug activo, Flask muestra una consola interactiva que permite
# ejecutar código en el servidor: jamás debe estar encendido en producción.
MODO_DEBUG = os.environ.get('FLASK_DEBUG') == '1'

app = Flask(__name__)

# SEGURIDAD: clave secreta leída del entorno. Con ella se firman las cookies
# de sesión; si alguien la conoce puede falsificar una sesión de admin.
# Si no está definida se genera una aleatoria (las sesiones se pierden al
# reiniciar el servidor, pero nunca se usa una clave conocida).
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
if not os.environ.get('SECRET_KEY'):
    app.logger.warning('SECRET_KEY no definida: se usa una clave temporal aleatoria.')

# SEGURIDAD: configuración de la cookie de sesión.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # JavaScript no puede leer la cookie (mitiga robo por XSS)
    SESSION_COOKIE_SAMESITE='Lax',      # El navegador no la envía en peticiones POST desde otros sitios
    SESSION_COOKIE_SECURE=not MODO_DEBUG,  # En producción solo viaja por HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # La sesión expira tras 8 horas (un turno)
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # Rechaza peticiones de más de 1 MB
)

# SEGURIDAD: si la app corre detrás de un proxy (Render, Heroku, Nginx),
# esto permite conocer la IP real del cliente y si la conexión es HTTPS.
# Solo se activa con CONFIAR_PROXY=1, porque sin proxy un atacante podría
# falsificar la cabecera X-Forwarded-For.
if os.environ.get('CONFIAR_PROXY') == '1':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# SEGURIDAD: configuración de conexión a NeonDB PostgreSQL desde el entorno.
# Se acepta DATABASE_URL (formato típico de los servicios en la nube) o las
# variables separadas DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT.
DATABASE_URL = os.environ.get('DATABASE_URL')
DB_CONFIG = {
    'dbname': os.environ.get('DB_NAME', 'neondb'),
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', 5432)),
    'sslmode': 'require'
}

def get_db_connection():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL, sslmode='require', cursor_factory=RealDictCursor)
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    return conn

LOCAL_ZONE = ZoneInfo('America/Bogota')

def convertir_a_hora_local(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(LOCAL_ZONE)


# =====================================================================
# SEGURIDAD: Protección CSRF (Cross-Site Request Forgery)
# ---------------------------------------------------------------------
# Sin esto, una página maliciosa podría hacer que el navegador de un admin
# con sesión abierta envíe formularios a MotelFlow (crear usuarios, dar
# permisos, registrar ventas...). Cada sesión recibe un token aleatorio que
# debe acompañar toda petición POST: en formularios como campo oculto
# "csrf_token" y en fetch() como cabecera "X-CSRFToken".
# =====================================================================
def generar_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

# Permite usar {{ csrf_token() }} dentro de las plantillas
app.jinja_env.globals['csrf_token'] = generar_csrf_token

@app.before_request
def proteger_csrf():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    token_sesion = session.get('_csrf_token')
    token_enviado = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    # compare_digest compara en tiempo constante (evita ataques de temporización)
    if not token_sesion or not token_enviado or not secrets.compare_digest(token_sesion, token_enviado):
        app.logger.warning('CSRF inválido en %s desde %s', request.path, request.remote_addr)
        abort(400)


# =====================================================================
# SEGURIDAD: Cabeceras HTTP de seguridad en todas las respuestas
# =====================================================================
@app.after_request
def agregar_cabeceras_seguridad(respuesta):
    # Impide que el navegador "adivine" el tipo de archivo (evita ejecutar subidas como script)
    respuesta.headers['X-Content-Type-Options'] = 'nosniff'
    # Impide que otra web incruste MotelFlow en un iframe (clickjacking)
    respuesta.headers['X-Frame-Options'] = 'DENY'
    # No envía la URL completa a sitios externos (p. ej. al abrir WhatsApp)
    respuesta.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Desactiva APIs del navegador que la app no usa
    respuesta.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # Política de contenido: solo se cargan scripts, estilos y medios del propio
    # servidor (y las fuentes de Google). 'unsafe-inline' es necesario porque las
    # plantillas usan <script> y onclick en línea.
    respuesta.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "media-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    # Con HTTPS, obliga al navegador a usar siempre HTTPS durante un año
    if request.is_secure:
        respuesta.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Las páginas internas no se guardan en caché: tras cerrar sesión, el botón
    # "Atrás" no debe mostrar datos de usuarios, ventas o turnos
    if 'usuario' in session:
        respuesta.headers['Cache-Control'] = 'no-store'
    return respuesta


# =====================================================================
# SEGURIDAD: Manejadores de errores
# ---------------------------------------------------------------------
# Muestran un mensaje genérico en lugar de detalles internos (rutas,
# consultas SQL, trazas de Python) que le darían pistas a un atacante.
# =====================================================================
MENSAJES_ERROR = {
    400: 'Solicitud inválida o formulario vencido. Recarga la página e inténtalo de nuevo.',
    403: 'No tienes permisos para realizar esta acción.',
    404: 'La página solicitada no existe.',
    405: 'Método no permitido.',
    413: 'La información enviada es demasiado grande.',
    500: 'Ocurrió un error interno. Inténtalo más tarde.',
}

def responder_error(codigo):
    mensaje = MENSAJES_ERROR.get(codigo, 'Error')
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'ok': False, 'msg': mensaje}), codigo
    return f'<h2>Error {codigo}</h2><p>{mensaje}</p><p><a href="/">Volver al inicio</a></p>', codigo

for _codigo in MENSAJES_ERROR:
    app.register_error_handler(_codigo, lambda e, c=_codigo: responder_error(c))


# =====================================================================
# SEGURIDAD: Funciones de validación de datos de entrada
# ---------------------------------------------------------------------
# Nunca se confía en lo que llega del navegador: el usuario puede modificar
# el HTML o enviar peticiones a mano. Cada función devuelve None si el dato
# no es válido.
# =====================================================================
REGEX_CORREO = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def leer_entero(valor, minimo=None, maximo=None):
    try:
        numero = int(str(valor).strip())
    except (TypeError, ValueError):
        return None
    if (minimo is not None and numero < minimo) or (maximo is not None and numero > maximo):
        return None
    return numero

def leer_decimal(valor, minimo=Decimal('0'), maximo=Decimal('1000000000')):
    try:
        numero = Decimal(str(valor).strip())
    except (InvalidOperation, TypeError, ValueError):
        return None
    # is_finite descarta valores como "NaN" o "Infinity"
    if not numero.is_finite() or numero < minimo or numero > maximo:
        return None
    return numero

def leer_texto(valor, max_largo, requerido=True):
    texto = (valor or '').strip()
    if (requerido and not texto) or len(texto) > max_largo:
        return None
    return texto


# =====================================================================
# SEGURIDAD: Contraseñas cifradas (hash)
# ---------------------------------------------------------------------
# Antes las contraseñas se guardaban en texto plano: cualquiera con acceso
# a la BD las veía. Ahora se guarda un hash (scrypt, con sal aleatoria) que
# no se puede revertir. Los usuarios antiguos se migran automáticamente: la
# primera vez que inician sesión con su contraseña en texto plano, esta se
# reemplaza por su hash.
# =====================================================================
LONGITUD_MINIMA_CONTRASENA = 8
PREFIJOS_HASH = ('scrypt:', 'pbkdf2:')
# Hash ficticio para comparar cuando el correo no existe, así la respuesta
# tarda lo mismo y no revela qué correos están registrados
HASH_FICTICIO = generate_password_hash(secrets.token_hex(16))

def es_hash(contrasena_guardada):
    return (contrasena_guardada or '').startswith(PREFIJOS_HASH)

def verificar_contrasena(usuario, contrasena):
    guardada = usuario['contrasena'] or ''
    if es_hash(guardada):
        return check_password_hash(guardada, contrasena)
    # Contraseña antigua en texto plano: comparar y migrar a hash
    if secrets.compare_digest(guardada.encode('utf-8'), contrasena.encode('utf-8')):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE usuario SET contrasena = %s WHERE id = %s",
                    (generate_password_hash(contrasena), usuario['id']))
        conn.commit()
        cur.close()
        conn.close()
        return True
    return False


# =====================================================================
# SEGURIDAD: Límite de intentos de inicio de sesión (fuerza bruta)
# ---------------------------------------------------------------------
# Tras 5 intentos fallidos con el mismo correo desde la misma IP, se bloquea
# el login por 5 minutos. Se guarda en memoria del servidor (se reinicia al
# reiniciar la app), suficiente para frenar ataques automatizados.
# =====================================================================
MAX_INTENTOS_LOGIN = 5
MINUTOS_BLOQUEO = 5
intentos_login = {}  # clave -> {'fallos': int, 'bloqueado_hasta': timestamp}

def clave_intentos(correo):
    return f"{request.remote_addr}|{correo.lower()}"

def login_bloqueado(clave):
    registro = intentos_login.get(clave)
    return bool(registro and registro['bloqueado_hasta'] > time.time())

def registrar_fallo_login(clave):
    registro = intentos_login.setdefault(clave, {'fallos': 0, 'bloqueado_hasta': 0})
    registro['fallos'] += 1
    if registro['fallos'] >= MAX_INTENTOS_LOGIN:
        registro['fallos'] = 0
        registro['bloqueado_hasta'] = time.time() + MINUTOS_BLOQUEO * 60
        app.logger.warning('Login bloqueado temporalmente para %s', clave)


# Función para obtener usuario por correo
def obtener_usuario_por_correo(correo):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM usuario WHERE correo = %s", (correo,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    return usuario

# SEGURIDAD: devuelve el usuario de la sesión solo si sigue existiendo y está
# Activo. Si un admin desactiva a un colaborador, este pierde el acceso en su
# siguiente clic, aunque tenga la sesión abierta.
def obtener_usuario_actual():
    if 'usuario' not in session:
        return None
    usuario = obtener_usuario_por_correo(session['usuario'])
    if not usuario or (usuario.get('estado') or '').lower() != 'activo':
        session.clear()
        return None
    return usuario

def es_admin(usuario):
    return bool(usuario) and (usuario['rol'] or '').lower() == 'admin'

PANELES = ['habitaciones', 'turnos', 'inventario', 'ventas', 'nomina', 'usuarios', 'permisos', 'aseo']

# Función para obtener los permisos del usuario actual
def obtener_permisos_usuario():
    usuario = obtener_usuario_actual()
    if not usuario:
        return []
    if es_admin(usuario):
        return list(PANELES)
    else:
        # Colaborador: obtener permisos asignados
        if usuario.get('permisos'):
            # SEGURIDAD: solo se aceptan nombres de panel conocidos
            return [p.strip() for p in usuario['permisos'].split(',') if p.strip() in PANELES]
        return []

# Función para validar si el usuario tiene permiso para un panel
def tiene_permiso(panel_requerido):
    permisos = obtener_permisos_usuario()
    return panel_requerido in permisos

# Función para redirigir si no tiene permiso
def validar_acceso(panel_requerido):
    if not tiene_permiso(panel_requerido):
        # SEGURIDAD: se registra el intento de acceso no autorizado
        app.logger.warning('Acceso denegado a "%s" para %s', panel_requerido, session.get('usuario', 'anónimo'))
        flash('No tienes permisos para acceder a este módulo.')
        return redirect(url_for('panel_admin'))
    return None

# Función para obtener el turno abierto de un usuario
def obtener_turno_abierto_usuario(usuario_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM turno WHERE id_usuario = %s AND estado IN ('Abierto', 'abierto') ORDER BY id DESC LIMIT 1", (usuario_id,))
    turno = cur.fetchone()
    cur.close()
    conn.close()
    return turno

DECORACIONES = [
    {
        'id': 1,
        'nombre': 'Decoración basica',
        'descripcion': 'Pétalos de rosa, velas aromáticas y luz tenue.',
        'precio': 25000,
        'imagen': 'img/aniversario.jpg'
    }
]

# Catálogo de habitaciones
ROOMS = [
    {
        'id': 1,
        'nombre': 'Habitación rubí',
        'descripcion': 'Habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación y baño privado.',
        'precio': 60000,
        'imagen': 'img/rubi.jpeg'
    },
    {
        'id': 2,
        'nombre': 'Habitación Zafiro',
        'descripcion': 'Ambiente íntimo, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado y camilla.',
        'precio': 65000,
        'imagen': 'img/zafiro.jpeg'
    },
    {
        'id': 3,
        'nombre': 'Habitación Diamante',
        'descripcion': 'Comodidad y privacidad, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado, camilla y jacuzzi.',
        'precio': 90000,
        'imagen': 'img/diamante.jpeg'
    },
    {
        'id': 4,
        'nombre': 'Habitación platino',
        'descripcion': 'Espacio moderno, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado, camilla, jacuzzi, sillon, sonio de alta calidad y sauna a petición',
        'precio': 120000,
        'imagen': 'img/platino.jpeg'
    }
]


TIEMPOS = [
    {
        'id': 'rato',
        'nombre': 'Rato',
        'precio': 40000
    },
    {
        'id': 'amanecida',
        'nombre': 'Amanecida',
        'precio': 70000
    }
]

# SEGURIDAD: valores permitidos para los campos que vienen de listas fijas
ROLES_VALIDOS = ('admin', 'colaborador')
ESTADOS_USUARIO = ('Activo', 'Inactivo')
ESTADOS_HABITACION = ('Libre', 'Ocupada', 'Sucia')
TIEMPOS_HABITACION = ('rato', 'amanecida')
# Las reservas viven en la cookie de sesión (máx. ~4 KB), por eso se limitan
MAX_RESERVAS_CARRITO = 10

@app.route('/')
def index():
    return render_template('index.html', rooms=ROOMS, decoraciones=DECORACIONES, tiempos=TIEMPOS)


@app.route('/cart')
def cart():
    reservas = session.get('reservas', [])
    total = 0
    for r in reservas:
        total += r['habitacion']['precio']
        for deco in r.get('decoraciones', []):
            total += deco['precio']
        if 'tiempo' in r and r['tiempo']:
            total += r['tiempo']['precio']
    return render_template('cart.html', reservas=reservas, total=total)

# Ruta para reservar habitación, decoraciones y tiempo
@app.route('/reservar', methods=['POST'])
def reservar():
    # SEGURIDAD: antes int(None) hacía caer la app con error 500
    room_id = leer_entero(request.form.get('room_id'), minimo=1)
    deco_ids = request.form.getlist('decoraciones')
    tiempo_id = request.form.get('tiempo')
    # Los precios salen siempre del catálogo del servidor, nunca del formulario
    room = next((r for r in ROOMS if r['id'] == room_id), None)
    decoraciones = [d for d in DECORACIONES if str(d['id']) in deco_ids]
    tiempo = next((t for t in TIEMPOS if t['id'] == tiempo_id), None)
    if room:
        reservas = session.get('reservas', [])
        if len(reservas) >= MAX_RESERVAS_CARRITO:
            flash('Has alcanzado el máximo de reservas en el carrito.')
            return redirect(url_for('cart'))
        reservas.append({'habitacion': room, 'decoraciones': decoraciones, 'tiempo': tiempo})
        session['reservas'] = reservas
    return redirect(url_for('cart'))



# Ruta de login con autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = (request.form.get('usuario') or '').strip()
        contrasena = request.form.get('contrasena') or ''
        clave = clave_intentos(correo)

        # SEGURIDAD: bloqueo temporal tras demasiados intentos fallidos
        if login_bloqueado(clave):
            flash(f'Demasiados intentos fallidos. Espera {MINUTOS_BLOQUEO} minutos e inténtalo de nuevo.')
            return redirect(url_for('login'))

        # SEGURIDAD: se descartan entradas vacías o absurdamente largas
        usuario = None
        if correo and contrasena and len(correo) <= 100 and len(contrasena) <= 128:
            usuario = obtener_usuario_por_correo(correo)

        if usuario and verificar_contrasena(usuario, contrasena):
            if (usuario.get('estado') or '').lower() != 'activo':
                flash('Tu usuario está inactivo. Comunícate con el administrador.')
                return redirect(url_for('login'))
            intentos_login.pop(clave, None)
            # SEGURIDAD: se limpia la sesión anterior antes de autenticar
            # (evita la "fijación de sesión") y se genera un token CSRF nuevo
            session.clear()
            session.permanent = True
            session['usuario'] = usuario['correo']
            session['rol'] = usuario['rol']
            app.logger.info('Inicio de sesión exitoso: %s', usuario['correo'])
            # Ambos Admin y Colaborador van a /admin que redirige a /panel_admin
            return redirect(url_for('admin'))
        else:
            if not usuario:
                # Misma demora que con un usuario real (no revela si el correo existe)
                check_password_hash(HASH_FICTICIO, contrasena)
            registrar_fallo_login(clave)
            app.logger.warning('Inicio de sesión fallido para "%s" desde %s', correo[:100], request.remote_addr)
            # Mensaje genérico: no se indica si falló el correo o la contraseña
            flash('Usuario o contraseña incorrectos.')
            return redirect(url_for('login'))
    return render_template('login.html')

# Ruta para eliminar una reserva por índice
@app.route('/eliminar/<int:idx>', methods=['POST'])
def eliminar(idx):
    reservas = session.get('reservas', [])
    if 0 <= idx < len(reservas):
        reservas.pop(idx)
        session['reservas'] = reservas
    return redirect(url_for('cart'))



# Ruta para empleados
@app.route('/empleados', methods=['GET'])
def empleados():
    usuario = obtener_usuario_actual()
    if not usuario:
        return redirect(url_for('login'))
    if usuario['rol'].lower() != 'colaborador':
        flash('Acceso restringido.')
        return redirect(url_for('login'))

    turno_abierto = False
    fecha_apertura = None
    # Si ya existe un turno abierto en sesión, verificar en la BD.
    if 'turno_id' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        # SEGURIDAD: se verifica que el turno pertenezca al usuario de la sesión
        cur.execute("SELECT * FROM turno WHERE id = %s AND id_usuario = %s AND estado IN ('Abierto', 'abierto')",
                    (session['turno_id'], usuario['id']))
        turno = cur.fetchone()
        cur.close()
        conn.close()
        if turno:
            turno_abierto = True
            fecha_apertura = turno['fecha_apertura']
    if not turno_abierto:
        turno = obtener_turno_abierto_usuario(usuario['id'])
        if turno:
            session['turno_id'] = turno['id']
            turno_abierto = True
            fecha_apertura = turno['fecha_apertura']

    permisos = obtener_permisos_usuario()
    return render_template('empleados.html', turno_abierto=turno_abierto, fecha_apertura=fecha_apertura, permisos=permisos)

# Ruta para panel de habitaciones

# --- CRUD Habitaciones ---
@app.route('/habitaciones', methods=['GET', 'POST'])
def habitaciones():
    # Validar acceso
    acceso_negado = validar_acceso('habitaciones')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        # Registrar nueva habitación
        # SEGURIDAD: validación de longitud (según la BD) y de precio positivo
        numero = leer_texto(request.form.get('numero'), 10)
        tipo = leer_texto(request.form.get('tipo'), 50)
        precio = leer_decimal(request.form.get('precio_estandar'))
        if numero is None or tipo is None or precio is None:
            flash('Datos de habitación inválidos.')
        else:
            cur.execute("INSERT INTO habitacion (numero, tipo, precio_estandar) VALUES (%s, %s, %s)", (numero, tipo, precio))
            conn.commit()
    cur.execute("SELECT * FROM habitacion ORDER BY id")
    habitaciones = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('habitaciones.html', habitaciones=habitaciones)


@app.route('/admin', methods=['GET'])
def admin():
    return render_template('admin.html')

# Crear turno (POST desde empleados.html)
@app.route('/abrir_turno', methods=['POST'])
def abrir_turno():
    usuario = obtener_usuario_actual()
    if not usuario:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    # SEGURIDAD: get_json(silent=True) evita un error 500 si el cuerpo no es JSON
    datos = request.get_json(silent=True) or {}
    base_caja = leer_decimal(datos.get('base_caja'))
    if base_caja is None:
        return jsonify({'ok': False, 'msg': 'Monto inválido'}), 400
    # Insertar turno
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO turno (id_usuario, base_caja, estado, recaudo_total)
        VALUES (%s, %s, 'Abierto', 0)
        RETURNING id, fecha_apertura
    """, (usuario['id'], base_caja))
    turno = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    session['turno_id'] = turno['id']
    fecha_apertura_local = convertir_a_hora_local(turno['fecha_apertura']).strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({'ok': True, 'turno_id': turno['id'], 'fecha_apertura': fecha_apertura_local})

# Cerrar turno (POST desde empleados.html)
@app.route('/cerrar_turno', methods=['POST'])
def cerrar_turno():
    if 'usuario' not in session or 'turno_id' not in session:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    turno_id = session['turno_id']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE turno SET fecha_cierre = CURRENT_TIMESTAMP, estado = 'Cerrado'
        WHERE id = %s
    """, (turno_id,))
    conn.commit()
    cur.close()
    conn.close()
    # SEGURIDAD: se borra toda la sesión, no solo algunas claves
    session.clear()
    return jsonify({'ok': True})

# Logout para Admin (sin registrar turno)
# SEGURIDAD: ahora es POST (con token CSRF). Con GET, cualquier página externa
# podía cerrar la sesión del usuario con una simple etiqueta <img>.
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.')
    return redirect(url_for('login'))

# Cerrar sesión (GET desde header_colaborador.html)
@app.route('/cerrar_sesion', methods=['POST'])
def cerrar_sesion():
    if 'usuario' not in session or 'turno_id' not in session:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    turno_id = session['turno_id']
    datos = request.get_json(silent=True)
    observaciones = ''
    if datos:
        observaciones = datos.get('observaciones', '')
    else:
        observaciones = request.form.get('observaciones', '')
    # SEGURIDAD: límite de longitud para las observaciones
    observaciones = str(observaciones or '').strip()[:1000]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE turno SET fecha_cierre = CURRENT_TIMESTAMP, estado = 'Cerrado', observaciones = %s
        WHERE id = %s
    """, (observaciones, turno_id))
    conn.commit()
    cur.close()
    conn.close()
    session.clear()
    return jsonify({'ok': True})

# --- RUTAS DE TURNOS (deben ir después de la definición de app) ---
# (Mover esto después de la definición de app)

# Panel de administración principal
@app.route('/panel_admin')
def panel_admin():
    permisos = obtener_permisos_usuario()
    es_colaborador = False

    usuario = obtener_usuario_actual()
    if usuario:
        es_colaborador = usuario['rol'].lower() == 'colaborador'

        # Si es Admin, mostrar vista admin_panel.html sin turnos
        if es_admin(usuario):
            return render_template('admin_panel.html', permisos=permisos)

        # Si es Colaborador, verificar turno abierto
        if es_colaborador:
            turno_abierto = False
            fecha_apertura = None

            # Verificar si tiene turno abierto
            if 'turno_id' in session:
                conn = get_db_connection()
                cur = conn.cursor()
                # SEGURIDAD: el turno debe pertenecer al usuario de la sesión
                cur.execute("SELECT * FROM turno WHERE id = %s AND id_usuario = %s AND estado IN ('Abierto', 'abierto')",
                            (session['turno_id'], usuario['id']))
                turno = cur.fetchone()
                cur.close()
                conn.close()
                if turno:
                    turno_abierto = True
                    fecha_apertura = convertir_a_hora_local(turno['fecha_apertura']).strftime('%Y-%m-%d %H:%M:%S')

            if not turno_abierto:
                turno = obtener_turno_abierto_usuario(usuario['id'])
                if turno:
                    session['turno_id'] = turno['id']
                    turno_abierto = True
                    fecha_apertura = convertir_a_hora_local(turno['fecha_apertura']).strftime('%Y-%m-%d %H:%M:%S')

            return render_template('panel_admin.html', permisos=permisos, turno_abierto=turno_abierto,
                                 fecha_apertura=fecha_apertura, es_colaborador=es_colaborador)

    return redirect(url_for('login'))

# Paneles individuales
@app.route('/turnos')
def turnos():
    # Validar acceso
    acceso_negado = validar_acceso('turnos')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Obtener todos los turnos (uniendo con la tabla usuario para ver el nombre)
    cur.execute("""
        SELECT t.*, u.nombres as nombre_usuario
        FROM turno t
        JOIN usuario u ON t.id_usuario = u.id
        ORDER BY t.fecha_apertura DESC
    """)
    todos_los_turnos = cur.fetchall()

    # 2. Obtener solo el último registro
    cur.execute("""
        SELECT t.*, u.nombres as nombre_usuario
        FROM turno t
        JOIN usuario u ON t.id_usuario = u.id
        ORDER BY t.id DESC LIMIT 1
    """)
    ultimo_turno = cur.fetchone()

    # Convertir fechas a hora local de Colombia
    for turno in todos_los_turnos:
        if turno.get('fecha_apertura'):
            turno['fecha_apertura'] = convertir_a_hora_local(turno['fecha_apertura'])
        if turno.get('fecha_cierre'):
            turno['fecha_cierre'] = convertir_a_hora_local(turno['fecha_cierre'])
    if ultimo_turno:
        if ultimo_turno.get('fecha_apertura'):
            ultimo_turno['fecha_apertura'] = convertir_a_hora_local(ultimo_turno['fecha_apertura'])
        if ultimo_turno.get('fecha_cierre'):
            ultimo_turno['fecha_cierre'] = convertir_a_hora_local(ultimo_turno['fecha_cierre'])

    cur.close()
    conn.close()
    return render_template('turnos.html', turnos=todos_los_turnos, ultimo=ultimo_turno)

# --- CRUD Inventario ---
@app.route('/inventario', methods=['GET', 'POST'])
def inventario():
    # Validar acceso
    acceso_negado = validar_acceso('inventario')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        # SEGURIDAD: stock y precios deben ser números no negativos
        nombre = leer_texto(request.form.get('nombre'), 100)
        stock_actual = leer_entero(request.form.get('stock_actual'), minimo=0, maximo=1000000)
        precio_costo = leer_decimal(request.form.get('precio_costo'))
        precio_venta = leer_decimal(request.form.get('precio_venta'))
        stock_minimo = leer_entero(request.form.get('stock_minimo'), minimo=0, maximo=1000000)
        if None in (nombre, stock_actual, precio_costo, precio_venta, stock_minimo):
            flash('Datos de producto inválidos.')
        else:
            cur.execute("INSERT INTO inventario (nombre, stock_actual, precio_costo, precio_venta, stock_minimo) VALUES (%s, %s, %s, %s, %s)",
                (nombre, stock_actual, precio_costo, precio_venta, stock_minimo))
            conn.commit()
    cur.execute("SELECT * FROM inventario ORDER BY id")
    productos = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('inventario.html', productos=productos)


# --- Registro de Ventas ---


# --- Registro de Ventas mejorado ---

# Carrito de productos por habitación en sesión
@app.route('/ventas', methods=['GET', 'POST'])
def ventas():
    # Validar acceso
    acceso_negado = validar_acceso('ventas')
    if acceso_negado:
        return acceso_negado

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM inventario ORDER BY nombre")
    productos = cur.fetchall()
    cur.execute("SELECT * FROM habitacion ORDER BY numero")
    habitaciones = cur.fetchall()
    usuario_id = None
    if 'usuario' in session:
        cur.execute("SELECT id FROM usuario WHERE correo=%s", (session['usuario'],))
        u = cur.fetchone()
        if u:
            usuario_id = u['id']
    mensaje = None
    # Carrito de productos por habitación
    if 'carrito' not in session:
        session['carrito'] = {}
    carrito = session['carrito']
    if request.method == 'POST':
        # SEGURIDAD: los identificadores deben ser enteros y la cantidad positiva.
        # Antes una cantidad negativa AUMENTABA el stock y restaba del recaudo.
        id_hab_num = leer_entero(request.form.get('id_habitacion'), minimo=1)
        id_habitacion = str(id_hab_num) if id_hab_num else None
        id_producto = leer_entero(request.form.get('id_producto'), minimo=1)
        cantidad = leer_entero(request.form.get('cantidad'), minimo=1, maximo=1000)
        accion = request.form.get('accion')
        if not id_habitacion:
            mensaje = 'Habitación inválida.'
        elif accion == 'agregar_producto' and id_producto and cantidad:
            # Agregar producto al carrito
            if id_habitacion not in carrito:
                carrito[id_habitacion] = []
            carrito[id_habitacion].append({'id_producto': id_producto, 'cantidad': cantidad})
            session['carrito'] = carrito
            mensaje = 'Producto agregado al carrito.'
        elif accion == 'registrar_venta' and usuario_id:
            # Registrar venta solo al ocupar
            productos_hab = carrito.get(id_habitacion, [])
            stock_ok = True
            for item in productos_hab:
                cur.execute("SELECT precio_venta, stock_actual FROM inventario WHERE id = %s", (item['id_producto'],))
                prod = cur.fetchone()
                if not prod or prod['stock_actual'] < item['cantidad']:
                    mensaje = 'Stock insuficiente para algún producto.'
                    stock_ok = False
                    break
            if stock_ok:
                total = 0
                for item in productos_hab:
                    cur.execute("SELECT precio_venta FROM inventario WHERE id = %s", (item['id_producto'],))
                    prod = cur.fetchone()
                    total += float(prod['precio_venta']) * item['cantidad']
                # Sumar valor de la habitación
                cur.execute("SELECT precio_estandar FROM habitacion WHERE id = %s", (id_habitacion,))
                hab = cur.fetchone()
                if hab:
                    total += float(hab['precio_estandar'])
                for item in productos_hab:
                    cur.execute("SELECT precio_venta FROM inventario WHERE id = %s", (item['id_producto'],))
                    prod = cur.fetchone()
                    total_pago = float(prod['precio_venta']) * item['cantidad']
                    cur.execute("INSERT INTO venta (id_usuario, id_habitacion, id_producto, cantidad, total_pago) VALUES (%s, %s, %s, %s, %s)",
                        (usuario_id, id_habitacion, item['id_producto'], item['cantidad'], total_pago))
                    cur.execute("UPDATE inventario SET stock_actual = stock_actual - %s WHERE id = %s", (item['cantidad'], item['id_producto']))
                # Actualizar recaudo total del turno si es colaborador con turno abierto
                if 'turno_id' in session and session.get('rol', '').lower() == 'colaborador':
                    cur.execute("UPDATE turno SET recaudo_total = COALESCE(recaudo_total, 0) + %s WHERE id = %s", (total, session['turno_id']))
                conn.commit()
                mensaje = f'Venta registrada. Total: ${total}'
                carrito.pop(id_habitacion, None)
                session['carrito'] = carrito
        else:
            mensaje = 'Acción no válida o datos incompletos.'
    # Mostrar ventas
    cur.execute("""
        SELECT v.*, u.nombres as usuario, h.numero as habitacion, i.nombre as producto
        FROM venta v
        JOIN usuario u ON v.id_usuario = u.id
        LEFT JOIN habitacion h ON v.id_habitacion = h.id
        JOIN inventario i ON v.id_producto = i.id
        ORDER BY v.fecha_venta DESC
    """)
    ventas = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('ventas.html', productos=productos, habitaciones=habitaciones, ventas=ventas, mensaje=mensaje, carrito=carrito)

@app.route('/nomina')
def nomina():
    # Validar acceso
    acceso_negado = validar_acceso('nomina')
    if acceso_negado:
        return acceso_negado

    return render_template('nomina.html')

@app.route('/api/habitacion_estado/<int:hab_id>', methods=['POST'])
def api_habitacion_estado(hab_id):
    # SEGURIDAD: esta API no tenía ninguna validación: cualquier persona, sin
    # iniciar sesión, podía cambiar el estado de las habitaciones.
    if not (tiene_permiso('ventas') or tiene_permiso('habitaciones')):
        return jsonify({'ok': False, 'msg': 'No autorizado'}), 403
    data = request.get_json(silent=True) or {}
    estado = data.get('estado')
    tiempo = data.get('tiempo')
    # SEGURIDAD: solo se aceptan los estados y tiempos conocidos
    if estado not in ESTADOS_HABITACION or (tiempo and tiempo not in TIEMPOS_HABITACION):
        return jsonify({'ok': False, 'msg': 'Estado o tiempo inválido'}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    if tiempo:
        cur.execute("UPDATE habitacion SET estado=%s, tiempo=%s WHERE id=%s", (estado, tiempo, hab_id))
    else:
        cur.execute("UPDATE habitacion SET estado=%s, tiempo=NULL WHERE id=%s", (estado, hab_id))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'ok': True})


# SEGURIDAD: columnas de usuario que se envían a las plantillas. Se excluye
# "contrasena" para que el hash nunca llegue al HTML del navegador.
COLUMNAS_USUARIO_PUBLICAS = "id, documento, nombres, apellidos, rol, celular, correo, estado, funcion, permisos"

# --- PANEL: Crear usuario ---
@app.route('/usuarios', methods=['GET', 'POST'])
def usuarios():
    # Validar acceso
    acceso_negado = validar_acceso('usuarios')
    if acceso_negado:
        return acceso_negado

    usuario_sesion = obtener_usuario_actual()
    conn = get_db_connection()
    cur = conn.cursor()
    mensaje = None
    if request.method == 'POST':
        id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1) if request.form.get('id_usuario') else None
        # SEGURIDAD: validación de cada campo según los límites de la BD
        documento = leer_texto(request.form.get('documento'), 20)
        nombres = leer_texto(request.form.get('nombres'), 100)
        apellidos = leer_texto(request.form.get('apellidos'), 100)
        rol = (request.form.get('rol') or '').strip().lower()
        celular = leer_texto(request.form.get('celular'), 20, requerido=False)
        correo = leer_texto(request.form.get('correo'), 100)
        contrasena = request.form.get('contrasena') or ''
        estado = request.form.get('estado') or 'Activo'
        funcion = leer_texto(request.form.get('funcion'), 200, requerido=False)

        usuario_actual = None
        if id_usuario:
            cur.execute("SELECT permisos, rol FROM usuario WHERE id=%s", (id_usuario,))
            usuario_actual = cur.fetchone()

        errores = []
        if request.form.get('id_usuario') and not usuario_actual:
            errores.append('El usuario a editar no existe.')
        if None in (documento, nombres, apellidos, celular, funcion):
            errores.append('Revisa los campos: hay datos vacíos o demasiado largos.')
        if correo is None or not REGEX_CORREO.match(correo):
            errores.append('Correo inválido.')
        if rol not in ROLES_VALIDOS:
            errores.append('Rol inválido.')
        if estado not in ESTADOS_USUARIO:
            errores.append('Estado inválido.')
        # Al crear, la contraseña es obligatoria; al editar, vacía = no cambiarla
        if (not id_usuario or contrasena) and not (LONGITUD_MINIMA_CONTRASENA <= len(contrasena) <= 128):
            errores.append(f'La contraseña debe tener entre {LONGITUD_MINIMA_CONTRASENA} y 128 caracteres.')
        # SEGURIDAD: solo un admin puede crear administradores o modificar a un
        # admin; así un colaborador con permiso "usuarios" no puede escalar privilegios
        if not es_admin(usuario_sesion) and (rol == 'admin' or es_admin(usuario_actual)):
            errores.append('Solo un administrador puede crear o modificar administradores.')
        # SEGURIDAD: el correo es el usuario de login, no puede repetirse
        if correo:
            cur.execute("SELECT id FROM usuario WHERE LOWER(correo) = LOWER(%s) AND id <> %s", (correo, id_usuario or 0))
            if cur.fetchone():
                errores.append('Ya existe un usuario con ese correo.')

        if errores:
            mensaje = ' '.join(errores)
        elif id_usuario:  # Actualizar
            # Si es admin, asignar todos los permisos; si es colaborador, mantener los que ya tiene
            if rol == 'admin':
                permisos = ','.join(PANELES)
            else:
                # Mantener permisos existentes si es colaborador
                permisos = usuario_actual['permisos'] or ''
            cur.execute("UPDATE usuario SET documento=%s, nombres=%s, apellidos=%s, rol=%s, celular=%s, correo=%s, estado=%s, funcion=%s, permisos=%s WHERE id=%s",
                (documento, nombres, apellidos, rol, celular, correo, estado, funcion, permisos, id_usuario))
            if contrasena:
                # SEGURIDAD: la contraseña se guarda cifrada
                cur.execute("UPDATE usuario SET contrasena=%s WHERE id=%s", (generate_password_hash(contrasena), id_usuario))
            conn.commit()
            mensaje = 'Usuario actualizado.'
        else:  # Crear
            # Nuevos usuarios colaboradores sin permisos
            if rol == 'admin':
                permisos = ','.join(PANELES)
            else:
                permisos = ''  # Colaborador sin permisos inicialmente
            cur.execute("INSERT INTO usuario (documento, nombres, apellidos, rol, celular, correo, contrasena, estado, funcion, permisos) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (documento, nombres, apellidos, rol, celular, correo, generate_password_hash(contrasena), estado, funcion, permisos))
            conn.commit()
            mensaje = 'Usuario creado.'
    cur.execute(f"SELECT {COLUMNAS_USUARIO_PUBLICAS} FROM usuario ORDER BY id")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('usuarios.html', usuarios=usuarios, mensaje=mensaje)

# --- PANEL: Conceder permisos ---
@app.route('/permisos', methods=['GET', 'POST'])
def permisos():
    # Validar acceso
    acceso_negado = validar_acceso('permisos')
    if acceso_negado:
        return acceso_negado

    usuario_sesion = obtener_usuario_actual()
    conn = get_db_connection()
    cur = conn.cursor()
    mensaje = None
    if request.method == 'POST':
        id_usuario = leer_entero(request.form.get('id_usuario'), minimo=1)
        # SEGURIDAD: se descartan paneles que no existan en la lista oficial
        paneles = [p for p in request.form.getlist('paneles') if p in PANELES]
        destino = None
        if id_usuario:
            cur.execute("SELECT id, rol FROM usuario WHERE id=%s", (id_usuario,))
            destino = cur.fetchone()
        if not destino:
            mensaje = 'Usuario inválido.'
        # SEGURIDAD: un colaborador no puede cambiar sus propios permisos ni los de un admin
        elif not es_admin(usuario_sesion) and (es_admin(destino) or destino['id'] == usuario_sesion['id']):
            mensaje = 'No puedes modificar los permisos de este usuario.'
        else:
            cur.execute("UPDATE usuario SET permisos=%s WHERE id=%s", (','.join(paneles), id_usuario))
            conn.commit()
            mensaje = 'Permisos actualizados.'
    cur.execute(f"SELECT {COLUMNAS_USUARIO_PUBLICAS} FROM usuario ORDER BY id")
    usuarios = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('permisos.html', usuarios=usuarios, paneles=PANELES, mensaje=mensaje)

# --- PANEL: Aseo general (vacío) ---
@app.route('/aseo')
def aseo():
    # Validar acceso
    acceso_negado = validar_acceso('aseo')
    if acceso_negado:
        return acceso_negado

    return render_template('aseo.html')

if __name__ == '__main__':
    app.run(debug=MODO_DEBUG)
