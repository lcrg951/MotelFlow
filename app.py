
from flask import Flask, render_template, redirect, url_for, request, session


app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Cambia esto por una clave segura en producción

DECORACIONES = [
    {
        'id': 1,
        'nombre': 'Decoración Romántica',
        'descripcion': 'Pétalos de rosa, velas aromáticas y luz tenue.',
        'precio': 600,
        'imagen': 'img/cumpleanos_especial.jpg'
    },
    {
        'id': 2,
        'nombre': 'Cumpleaños Especial',
        'descripcion': 'Globos, pastel pequeño y banner personalizado.',
        'precio': 800,
        'imagen': 'img/cumpleanos_especial.jpg'
    },
    {
        'id': 3,
        'nombre': 'Decoración Spa',
        'descripcion': 'Aromaterapia, batas y decoración relajante.',
        'precio': 700,
        'imagen': 'img/decoracion_spa.jpg'
    },
    {
        'id': 4,
        'nombre': 'Aniversario',
        'descripcion': 'Champagne, flores y decoración elegante.',
        'precio': 1000,
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
        'nombre': 'Habitación Estándar',
        'descripcion': 'Comodidad y privacidad, habitación de lujo con cama king size, tv de pantalla plana, servicio de habitación, baño privado, camilla y jacuzzi.',
        'precio': 90000,
        'imagen': 'img/diamante.jpeg'
    },
    {
        'id': 4,
        'nombre': 'Habitación Ejecutiva',
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


@app.route('/login', methods=['GET', 'POST'])
def login():
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
@app.route('/empleados', methods=['POST'])
def empleados():
    return render_template('empleados.html')

# Ruta para panel de habitaciones
@app.route('/habitaciones')
def habitaciones():
    return render_template('habitaciones.html', rooms=ROOMS)

@app.route('/admin', methods=['POST'])
def admin():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
