from flask import Flask, request, jsonify

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity, jwt_optional, get_jwt_claims
)
import datetime

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'test'

jwt = JWTManager(app)


@app.route('/')
def mainjwt():
    return 'main'
@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    return{
        'hello' : identity,
        'foo' : ['baz', 'bar']
    }

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'msg': 'Request is NOT JSON'})

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username:
        return jsonify({'msg': 'Missing Username Parameter'})
    if not password:
        return jsonify({'msg': 'Missing Password Parameter'})

    if username != 'username' or password != 'password':
        return jsonify({'msg': 'Bad username or password'})

    expires = datetime.timedelta(days=1)

    access_token = create_access_token(
        identity=username, expires_delta=expires)
    print(username, password, expires, access_token)

    return jsonify({'TOKEN': access_token}), 201


@app.route('/protected', methods=['GET'])
@jwt_required
# @jwt_optional
def protected():
    # current_user = get_jwt_identity()
    # if current_user:
    #     return jsonify(logged_in_as=current_user), 200
    # else:
    #     return jsonify(logged_in_as='Anonymous User'), 200
    claims = get_jwt_claims()
    return jsonify({
        'hello is' : claims['hello'],
        'foo is' : claims['foo'] 
    }), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
