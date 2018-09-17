import json
import psycopg2
import datetime

from Crypto.Cipher import AES
import binascii
import bcrypt
from psycopg2.extras import RealDictCursor

salt = b'$2b$12$h/8Z0LAm87pytJQs3EuHTu'


from flask import Flask, request, jsonify
app = Flask(__name__)


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
        public_key=post_data['public_key'],
        phone_number=post_data['phone_number'],
        ip='',
        port=8001,
        updated_at=datetime.datetime.now(),
        login_token=binascii.hexlify(login_token).decode()
    )
    pg_insert_dict(db_conn(), "user_ip", data)

    return jsonify(dict(
        token=token,
        success=True
    ))


@app.route('/user/verify/', methods=['POST'])
def verify_user():
    post_data = request.json

    dbc = db_conn()
    cur = dbc.cursor()
    cur.execute("SELECT login_token FROM user_ip WHERE phone_number = '{}'".format(post_data['phone_number']))
    results = cur.fetchall()

    success = bcrypt.checkpw(post_data['login_token'].encode('utf-8'), binascii.unhexlify(results[0][0]))
    return jsonify(dict(
        success=success
    ))


@app.route('/user/broadcast/', methods=['POST'])
def broadcast():
    # TODO JHILL: check their login credentials
    post_data = request.json

    dbc = db_conn()
    cur = dbc.cursor()
    cur.execute("""
        UPDATE user_ip 
        SET ip='{}', port={}
        WHERE phone_number='{}'
    """.format(post_data['ip'], post_data['port'], post_data['phone_number']))
    dbc.commit()

    return jsonify(dict(
        success=True
    ))


@app.route('/users/', methods=['GET'])
def users():
    # TODO JHILL: check their login credentials
    other_number = request.args.get('number')
    dbc = db_conn()
    cur = dbc.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT public_key, ip, port
        FROM user_ip
        WHERE phone_number='{}'
    """.format(other_number))

    return jsonify(dict(
        users=cur.fetchall(),
        success=True
    ))

