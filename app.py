# API para cambiar estado y tiempo de habitación
from flask import jsonify
# --- RUTAS DE TURNOS (deben ir después de la definición de app) ---
from flask import jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, redirect, url_for, request, session, flash



app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Cambia esto por una clave segura en producción

# Configuración de conexión a NeonDB PostgreSQL
DB_CONFIG = {
    'dbname': 'neondb',
    'user': 'neondb_owner',
    'password': 'npg_EZt5bfOFHhN9',
    'host': 'ep-holy-shadow-am69l4k1-pooler.c-5.us-east-1.aws.neon.tech',
    'port': 5432,
    'sslmode': 'require'
}

def get_db_connection():
    conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
    return conn

# Función para obtener usuario por correo
def obtener_usuario_por_correo(correo):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM usuario WHERE correo = %s", (correo,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    return usuario

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
    room_id = int(request.form.get('room_id'))
    deco_ids = request.form.getlist('decoraciones')
    tiempo_id = request.form.get('tiempo')
    room = next((r for r in ROOMS if r['id'] == room_id), None)
    decoraciones = [d for d in DECORACIONES if str(d['id']) in deco_ids]
    tiempo = next((t for t in TIEMPOS if t['id'] == tiempo_id), None)
    if room:
        reservas = session.get('reservas', [])
        reservas.append({'habitacion': room, 'decoraciones': decoraciones, 'tiempo': tiempo})
        session['reservas'] = reservas
    return redirect(url_for('cart'))



# Ruta de login con autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form.get('usuario')
        contrasena = request.form.get('contrasena')
        usuario = obtener_usuario_por_correo(correo)
        if usuario and usuario['contrasena'] == contrasena:
            session['usuario'] = usuario['correo']
            session['rol'] = usuario['rol']
            if usuario['rol'].lower() == 'colaborador':
                return redirect(url_for('empleados'))
            elif usuario['rol'].lower() == 'admin':
                return redirect(url_for('admin'))
            else:
                flash('Rol no autorizado.')
                return redirect(url_for('login'))
        else:
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
@app.route('/empleados', methods=['GET', 'POST'])
def empleados():
    return render_template('empleados.html')

# Ruta para panel de habitaciones

# --- CRUD Habitaciones ---
@app.route('/habitaciones', methods=['GET', 'POST'])
def habitaciones():
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        # Registrar nueva habitación
        numero = request.form['numero']
        tipo = request.form['tipo']
        precio = request.form['precio_estandar']
        cur.execute("INSERT INTO habitacion (numero, tipo, precio_estandar) VALUES (%s, %s, %s)", (numero, tipo, precio))
        conn.commit()
    cur.execute("SELECT * FROM habitacion ORDER BY id")
    habitaciones = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('habitaciones.html', habitaciones=habitaciones)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    return render_template('admin.html')

# Crear turno (POST desde empleados.html)
@app.route('/abrir_turno', methods=['POST'])
def abrir_turno():
    if 'usuario' not in session:
        return jsonify({'ok': False, 'msg': 'No autenticado'}), 401
    correo = session['usuario']
    usuario = obtener_usuario_por_correo(correo)
    if not usuario:
        return jsonify({'ok': False, 'msg': 'Usuario no encontrado'}), 404
    base_caja = request.json.get('base_caja')
    if base_caja is None:
        return jsonify({'ok': False, 'msg': 'Monto requerido'}), 400
    # Insertar turno
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO turno (id_usuario, base_caja)
        VALUES (%s, %s)
        RETURNING id, fecha_apertura
    """, (usuario['id'], base_caja))
    turno = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    session['turno_id'] = turno['id']
    return jsonify({'ok': True, 'turno_id': turno['id'], 'fecha_apertura': turno['fecha_apertura']})

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
    session.pop('turno_id', None)
    session.pop('usuario', None)
    session.pop('rol', None)
    return jsonify({'ok': True})

# --- RUTAS DE TURNOS (deben ir después de la definición de app) ---
# (Mover esto después de la definición de app)

# Panel de administración principal
@app.route('/panel_admin')
def panel_admin():
    return render_template('panel_admin.html')

# Paneles individuales
@app.route('/turnos')
def turnos():
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

    cur.close()
    conn.close()
    return render_template('turnos.html', turnos=todos_los_turnos, ultimo=ultimo_turno)


# --- CRUD Inventario ---
@app.route('/inventario', methods=['GET', 'POST'])
def inventario():
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        nombre = request.form['nombre']
        stock_actual = request.form['stock_actual']
        precio_costo = request.form['precio_costo']
        precio_venta = request.form['precio_venta']
        stock_minimo = request.form['stock_minimo']
        cur.execute("INSERT INTO inventario (nombre, stock_actual, precio_costo, precio_venta, stock_minimo) VALUES (%s, %s, %s, %s, %s)",
            (nombre, stock_actual, precio_costo, precio_venta, stock_minimo))
        conn.commit()
    cur.execute("SELECT * FROM inventario ORDER BY id")
    productos = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('inventario.html', productos=productos)


# --- Registro de Ventas ---

# --- Registro de Ventas con usuario de turno ---
@app.route('/ventas', methods=['GET', 'POST'])
def ventas():
    conn = get_db_connection()
    cur = conn.cursor()
    # Obtener datos para el formulario
    cur.execute("SELECT * FROM inventario ORDER BY nombre")
    productos = cur.fetchall()
    cur.execute("SELECT * FROM habitacion ORDER BY numero")
    habitaciones = cur.fetchall()
    # Obtener usuario del turno abierto
    usuario_id = None
    if 'usuario' in session:
        cur.execute("SELECT id FROM usuario WHERE correo=%s", (session['usuario'],))
        u = cur.fetchone()
        if u:
            usuario_id = u['id']
    mensaje = None
    if request.method == 'POST':
        id_habitacion = request.form['id_habitacion'] or None
        id_producto = request.form['id_producto']
        cantidad = int(request.form['cantidad'])
        # Obtener precio_venta
        cur.execute("SELECT precio_venta, stock_actual FROM inventario WHERE id = %s", (id_producto,))
        prod = cur.fetchone()
        if not prod or prod['stock_actual'] < cantidad or not usuario_id:
            mensaje = 'Stock insuficiente o usuario no autenticado.'
        else:
            total_pago = float(prod['precio_venta']) * cantidad
            cur.execute("INSERT INTO venta (id_usuario, id_habitacion, id_producto, cantidad, total_pago) VALUES (%s, %s, %s, %s, %s)",
                (usuario_id, id_habitacion, id_producto, cantidad, total_pago))
            cur.execute("UPDATE inventario SET stock_actual = stock_actual - %s WHERE id = %s", (cantidad, id_producto))
            conn.commit()
            mensaje = 'Venta registrada correctamente.'
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
    return render_template('ventas.html', productos=productos, habitaciones=habitaciones, ventas=ventas, mensaje=mensaje)

@app.route('/nomina')
def nomina():
    return render_template('nomina.html')

@app.route('/api/habitacion_estado/<int:hab_id>', methods=['POST'])
def api_habitacion_estado(hab_id):
    data = request.get_json()
    estado = data.get('estado')
    tiempo = data.get('tiempo')
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

if __name__ == '__main__':
    app.run(debug=True)
