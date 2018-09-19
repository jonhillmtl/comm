import json
import psycopg2
import datetime

from Crypto.Cipher import AES
import binascii
import bcrypt
from psycopg2.extras import RealDictCursor

# TODO JHILL: do something with this
salt = b'$2b$12$h/8Z0LAm87pytJQs3EuHTu'


from flask import Flask, request, jsonify
app = Flask(__name__)


# TODO JHILL: move these to a utility file and environment variables
def db_conn():
    return psycopg2.connect(
        **dict(host='localhost', user='jon', password='jon', port='5432', dbname='pckr')
    )


def pg_sql_format_value(v):
    if type(v) == str or type(v) == datetime.datetime:
        return "'{}'".format(v)
    else:
        return str(v)


def pg_insert_dict(conn, tablename, data, conflict=''):
    """
    conflict could be ON CONFLICT DO NOTHING
    """
    cur = conn.cursor()
    try:
        sql = """
            INSERT into {}
            ({})
            VALUES ({})
            {}
        """.format(
            tablename,
            ",".join(data.keys()),
            ",".join([pg_sql_format_value(v) for v in data.values()]),
            conflict
        )

        cur.execute(sql)
    except psycopg2.ProgrammingError:
        print("{} is invalid".format(sql))
    conn.commit()


@app.route('/user/initiate/', methods=['POST'])
def initiate_user():
    post_data = request.json

    # TODO JHILL: generate random token
    token = 'abcdefghjqwertererwwerwerrrwerewtt2232323wwqwqweeweqqwe'
    login_token = bcrypt.hashpw(token.encode('utf-8'), salt)

    data = dict(
        username=post_data['username'],
        ip='',
        port=8001,
        updated_at=datetime.datetime.now(),
        login_token=binascii.hexlify(login_token).decode()
    )
    pg_insert_dict(db_conn(), "users", data)

    return jsonify(dict(
        token=token,
        success=True
    ))


@app.route('/user/verify/', methods=['POST'])
def verify_user():
    post_data = request.json

    dbc = db_conn()
    cur = dbc.cursor()
    cur.execute("SELECT login_token FROM users WHERE username = '{}'".format(post_data['username']))
    results = cur.fetchall()

    success = bcrypt.checkpw(post_data['login_token'].encode('utf-8'), binascii.unhexlify(results[0][0]))
    return jsonify(dict(
        success=success
    ))


@app.route('/user/broadcast/', methods=['POST'])
def broadcast():
    # TODO JHILL: check their login credentials with a decorator
    post_data = request.json
    print(post_data)
    dbc = db_conn()
    cur = dbc.cursor()
    cur.execute("""
        UPDATE users 
        SET ip='{}', port={}
        WHERE username='{}'
    """.format(post_data['ip'], post_data['port'], post_data['username']))
    dbc.commit()

    return jsonify(dict(
        success=True
    ))


@app.route('/users/', methods=['GET'])
def users():
    # TODO JHILL: check their login credentials with a decorator
    username = request.args.get('username')
    dbc = db_conn()
    cur = dbc.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT ip, port
        FROM users
        WHERE username='{}'
    """.format(username))

    return jsonify(dict(
        users=cur.fetchall(),
        success=True
    ))


@app.route('/db/clear/', methods=['POST'])
def clear_db():
    dbc = db_conn()
    cur = dbc.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        DELETE FROM users
    """)
    dbc.commit()

    return jsonify(dict(
        success=True
    ))

